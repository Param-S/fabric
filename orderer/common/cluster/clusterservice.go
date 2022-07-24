/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cluster

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/util"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

//go:generate mockery --dir . --name ClusterStepStream --case underscore --output ./mocks/

// ClusterStepStream defines the gRPC stream for sending
// transactions, and receiving corresponding responses
type ClusterStepStream interface {
	Send(response *orderer.ClusterNodeServiceStepResponse) error
	Recv() (*orderer.ClusterNodeServiceStepRequest, error)
	grpc.ServerStream
}

/*
type AuthRequestVerifier interface {
	VerifyAuthRequest(orderer.ClusterNodeService_StepServer, *orderer.ClusterNodeServiceStepRequest, TLSSessionBindingGetter, SignatureVerifier) (string, error)
}
*/

type ChannelMembersConfig struct {
	LastUpdatedTime int64
	MemberMapping   map[uint64][]byte
}

// ClusterService implements the server API for ClusterNodeService service
type ClusterService struct {
	StreamCountReporter              *StreamCountReporter
	RequestHandler                   Handler
	Logger                           *flogging.FabricLogger
	StepLogger                       *flogging.FabricLogger
	MinimumExpirationWarningInterval time.Duration
	CertExpWarningThreshold          time.Duration
	MembershipByChannel              map[string]*ChannelMembersConfig
	Lock                             sync.RWMutex
	//AuthVerifier                     AuthRequestVerifier
}

type AuthRequestSignature struct {
	Version   int64
	Timestamp string
	FromId    string
	ToId      string
	Channel   string
}

// Step passes an implementation-specific message to another cluster member.
func (s *ClusterService) Step(stream orderer.ClusterNodeService_StepServer) error {
	s.StreamCountReporter.Increment()
	defer s.StreamCountReporter.Decrement()

	addr := util.ExtractRemoteAddress(stream.Context())
	commonName := commonNameFromContext(stream.Context())
	exp := s.initializeExpirationCheck(stream, addr, commonName)
	s.Logger.Debugf("Connection from %s(%s)", commonName, addr)
	defer s.Logger.Debugf("Closing connection from %s(%s)", commonName, addr)

	// On a new stream, auth request is the first msg
	request, err := stream.Recv()
	if err == io.EOF {
		s.Logger.Debugf("%s(%s) disconnected well before establishing the stream", commonName, addr)
		return nil
	}
	if err != nil {
		s.Logger.Warningf("Stream read from %s failed: %v", addr, err)
		return err
	}
	//channel, err := s.AuthVerifier.VerifyAuthRequest(stream, request, GetTLSSessionBinding, VerifySignature)
	authReq, configUpdatedTime, err := s.VerifyAuthRequest(stream, request)
	if err != nil {
		s.Logger.Warnf("service authentication failed with error: %v", err)
		return status.Errorf(codes.Unauthenticated, "access denied")
	}

	for {
		err := s.handleMessage(stream, addr, exp, authReq.Channel, authReq.FromId, configUpdatedTime)
		if err == io.EOF {
			s.Logger.Debugf("%s(%s) disconnected", commonName, addr)
			return nil
		}
		if err != nil {
			return err
		}
		// Else, no error occurred, so we continue to the next iteration
	}
}

/*
type (
	TLSSessionBindingGetter func(grpc.Stream, []byte) ([]byte, error)
	SignatureVerifier       func(identity []byte, msgHash []byte, signature []byte) error
)
*/

//func (s *ClusterService) VerifyAuthRequest(stream orderer.ClusterNodeService_StepServer, request *orderer.ClusterNodeServiceStepRequest, tlsBindingGetter TLSSessionBindingGetter, signatureVerifier SignatureVerifier) (orderer.NodeAuthRequest, error) {
func (s *ClusterService) VerifyAuthRequest(stream orderer.ClusterNodeService_StepServer, request *orderer.ClusterNodeServiceStepRequest) (*orderer.NodeAuthRequest, int64, error) {
	authReq := request.GetNodeAuthrequest()
	if authReq == nil {
		return nil, -1, errors.New("invalid request object")
	}

	bindingFieldsHash := GetSessionBindingHash(authReq)

	tlsBinding, err := GetTLSSessionBinding(stream, bindingFieldsHash)
	if err != nil {
		return nil, -1, errors.Wrap(err, "session binding read failed")
	}

	if bytes.Equal(tlsBinding, authReq.SessionBinding) {
		return nil, -1, errors.New("session binding mismatch")
	}

	msg, err := asn1.Marshal(AuthRequestSignature{
		Version:   int64(authReq.Version),
		Timestamp: authReq.Timestamp.String(),
		FromId:    strconv.FormatUint(authReq.FromId, 10),
		ToId:      strconv.FormatUint(authReq.ToId, 10),
		Channel:   authReq.Channel,
	})
	if err != nil {
		return nil, -1, errors.Wrap(err, "ASN encoding failed")
	}

	s.Lock.RLock()
	defer s.Lock.RUnlock()
	identity := s.MembershipByChannel[authReq.Channel].MemberMapping[authReq.FromId]
	if identity == nil {
		return nil, -1, errors.Errorf("node %d is not member of channel %s", authReq.FromId, authReq.Channel)
	}

	err = VerifySignature(identity, msg, authReq.Signature)
	if err != nil {
		return nil, -1, errors.Wrap(err, "signature mismatch")
	}

	return authReq, atomic.LoadInt64(&s.MembershipByChannel[authReq.Channel].LastUpdatedTime), nil
}

func (s *ClusterService) handleMessage(stream ClusterStepStream, addr string, exp *certificateExpirationCheck, channel string, sender uint64, streamRefTime int64) error {
	request, err := stream.Recv()
	if err == io.EOF {
		return err
	}
	if err != nil {
		s.Logger.Warningf("Stream read from %s failed: %v", addr, err)
		return err
	}
	if request == nil {
		return errors.Errorf("Request message is nil")
	}
	if streamRefTime != atomic.LoadInt64(&s.MembershipByChannel[channel].LastUpdatedTime) {
		return io.EOF
	}

	if s.StepLogger.IsEnabledFor(zap.DebugLevel) {
		nodeName := commonNameFromContext(stream.Context())
		s.StepLogger.Debugf("Received message from %s(%s): %v", nodeName, addr, clusterRequestAsString(request))
	}

	exp.checkExpiration(time.Now(), channel)

	if tranReq := request.GetNodeTranrequest(); tranReq != nil {
		submitReq := &orderer.SubmitRequest{
			Channel:           channel,
			LastValidationSeq: tranReq.LastValidationSeq,
			Payload:           tranReq.Payload,
		}
		return s.RequestHandler.OnSubmit(channel, sender, submitReq)
	} else if clusterConReq := request.GetNodeConrequest(); clusterConReq != nil {
		conReq := &orderer.ConsensusRequest{
			Channel:  channel,
			Payload:  clusterConReq.Payload,
			Metadata: clusterConReq.Metadata,
		}
		return s.RequestHandler.OnConsensus(channel, sender, conReq)
		//return s.Dispatcher.DispatchConsensus(stream.Context(), conReq)
	}
	return errors.Errorf("Message is neither a Submit nor Consensus request")
}

/*
func (s *ClusterService) handleSubmit(request *orderer.NodeTransactionOrderRequest, stream ClusterStepStream, addr string, channel string) error {
	submitReq := &orderer.SubmitRequest{
		Channel:           channel,
		LastValidationSeq: request.LastValidationSeq,
		Payload:           request.Payload,
	}
	err := s.Dispatcher.DispatchSubmit(stream.Context(), submitReq)
	if err != nil {
		s.Logger.Warningf("Handling of Submit() from %s failed: %v", addr, err)
		return err
	}
	return err
}
*/

func (s *ClusterService) initializeExpirationCheck(stream orderer.ClusterNodeService_StepServer, endpoint, nodeName string) *certificateExpirationCheck {
	expiresAt := time.Time{}
	cert := util.ExtractCertificateFromContext(stream.Context())
	if cert != nil {
		expiresAt = cert.NotAfter
	}

	return &certificateExpirationCheck{
		minimumExpirationWarningInterval: s.MinimumExpirationWarningInterval,
		expirationWarningThreshold:       s.CertExpWarningThreshold,
		expiresAt:                        expiresAt,
		endpoint:                         endpoint,
		nodeName:                         nodeName,
		alert: func(template string, args ...interface{}) {
			s.Logger.Warningf(template, args...)
		},
	}
}

func (c *ClusterService) ConfigureNodeCerts(channel string, newNodes []common.Consenter) error {
	if c.MembershipByChannel == nil {
		return errors.New("Nodes cert storage is not initialized")
	}

	c.Logger.Infof("Updating nodes identity, channel: %s, nodes: %v", channel, newNodes)

	c.Lock.Lock()
	defer c.Lock.Unlock()

	channelCert := c.MembershipByChannel[channel]
	if channelCert != nil {
		c.Logger.Debugf("Refreshing the %s channel nodes identities", channel)
		delete(c.MembershipByChannel, channel)
	}
	channelCert = &ChannelMembersConfig{}
	atomic.StoreInt64(&channelCert.LastUpdatedTime, time.Now().UnixNano())
	channelCert.MemberMapping = make(map[uint64][]byte)
	for _, nodeIdentity := range newNodes {
		channelCert.MemberMapping[uint64(nodeIdentity.Id)] = nodeIdentity.Identity
	}
	c.MembershipByChannel[channel] = channelCert
	return nil
}

func clusterRequestAsString(request *orderer.ClusterNodeServiceStepRequest) string {
	if request == nil {
		return "Request is nil"
	}
	switch t := request.GetPayload().(type) {
	case *orderer.ClusterNodeServiceStepRequest_NodeTranrequest:
		if t.NodeTranrequest == nil || t.NodeTranrequest.Payload == nil {
			return fmt.Sprintf("Empty SubmitRequest: %v", t.NodeTranrequest)
		}
		return fmt.Sprintf("SubmitRequest for channel %s with payload of size %d",
			"", len(t.NodeTranrequest.Payload.Payload))
	case *orderer.ClusterNodeServiceStepRequest_NodeConrequest:
		return fmt.Sprintf("ConsensusRequest for channel %s with payload of size %d",
			"", len(t.NodeConrequest.Payload))
	default:
		return fmt.Sprintf("unknown type: %v", request)
	}
}
