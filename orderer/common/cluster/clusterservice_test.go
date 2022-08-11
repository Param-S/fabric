/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cluster_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/hyperledger/fabric/common/util"
	comm_utils "github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/cluster/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	tstamp, _   = ptypes.TimestampProto(time.Now().UTC())
	authRequest = &orderer.NodeAuthRequest{
		Version:   0,
		FromId:    1,
		ToId:      2,
		Channel:   "mychannel",
		Timestamp: tstamp,
	}
	nodeAuthrequest = &orderer.ClusterNodeServiceStepRequest{
		Payload: &orderer.ClusterNodeServiceStepRequest_NodeAuthrequest{
			NodeAuthrequest: authRequest,
		},
	}
	nodeConsensusRequest = &orderer.ClusterNodeServiceStepRequest{
		Payload: &orderer.ClusterNodeServiceStepRequest_NodeConrequest{
			NodeConrequest: &orderer.NodeConsensusRequest{
				Payload: []byte{1, 2, 3},
			},
		},
	}
	nodeTranRequest = &orderer.ClusterNodeServiceStepRequest{
		Payload: &orderer.ClusterNodeServiceStepRequest_NodeTranrequest{
			NodeTranrequest: &orderer.NodeTransactionOrderRequest{
				LastValidationSeq: 0,
				Payload:           &common.Envelope{},
			},
		},
	}
	nodeInvalidRequest = &orderer.ClusterNodeServiceStepRequest{
		Payload: &orderer.ClusterNodeServiceStepRequest_NodeConrequest{
			NodeConrequest: nil,
		},
	}
	submitRequest = &orderer.StepRequest{
		Payload: &orderer.StepRequest_SubmitRequest{
			SubmitRequest: &orderer.SubmitRequest{
				LastValidationSeq: 0,
				Payload:           &common.Envelope{},
				Channel:           "mychannel",
			},
		},
	}
)

func createClusterService(t *testing.T) (*comm_utils.GRPCServer, orderer.ClusterNodeService_StepClient) {
	serverKeyPair, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)

	srvConfig := comm_utils.ServerConfig{
		SecOpts: comm_utils.SecureOptions{
			Key:         serverKeyPair.Key,
			Certificate: serverKeyPair.Cert,
			UseTLS:      true,
		},
	}
	gRPCServer, err := comm_utils.NewGRPCServer("127.0.0.1:", srvConfig)
	require.NoError(t, err)

	go gRPCServer.Start()

	tlsConf := &tls.Config{
		RootCAs: x509.NewCertPool(),
	}

	_ = tlsConf.RootCAs.AppendCertsFromPEM(ca.CertBytes())
	tlsOpts := grpc.WithTransportCredentials(credentials.NewTLS(tlsConf))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, _ := grpc.DialContext(ctx, gRPCServer.Address(), tlsOpts, grpc.WithBlock())

	cl := orderer.NewClusterNodeServiceClient(conn)
	stepStream, err := cl.Step(context.Background())
	require.NoError(t, err)

	return gRPCServer, stepStream
}

func TestClusterServiceStep(t *testing.T) {
	t.Run("Create authenticated stream successfully", func(t *testing.T) {
		var err error

		stream := &mocks.ClusterStepStream{}
		handler := &mocks.Handler{}

		server, stepStream := createClusterService(t)
		defer server.Stop()

		svc := &cluster.ClusterService{
			StreamCountReporter: &cluster.StreamCountReporter{
				Metrics: cluster.NewMetrics(&disabled.Provider{}),
			},
			Logger:              flogging.MustGetLogger("test"),
			StepLogger:          flogging.MustGetLogger("test"),
			MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
			RequestHandler:      handler,
		}

		stream.On("Context").Return(stepStream.Context())
		stream.On("Recv").Return(nodeAuthrequest, nil).Once()
		stream.On("Recv").Return(nodeConsensusRequest, nil).Once()
		stream.On("Recv").Return(nil, io.EOF).Once()

		bindingHash := cluster.GetSessionBindingHash(authRequest)
		authRequest.SessionBinding, _ = cluster.GetTLSSessionBinding(stepStream.Context(), bindingHash)

		asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
			Version:   int64(authRequest.Version),
			Timestamp: authRequest.Timestamp.String(),
			FromId:    strconv.FormatUint(authRequest.FromId, 10),
			ToId:      strconv.FormatUint(authRequest.ToId, 10),
			Channel:   authRequest.Channel,
		})

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		signer := signingIdentity{clientKeyPair1.Signer}
		sig, err := signer.Sign(asnSignFields)
		require.NoError(t, err)

		authRequest.Signature = sig

		handler.On("OnConsensus", authRequest.Channel, authRequest.FromId, mock.Anything).Return(nil).Once()

		svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})
		err = svc.Step(stream)
		require.NoError(t, err)
	})

	t.Run("Fail with error if first request not auth request message type", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		handler := &mocks.Handler{}

		svc := &cluster.ClusterService{
			StreamCountReporter: &cluster.StreamCountReporter{
				Metrics: cluster.NewMetrics(&disabled.Provider{}),
			},
			Logger:              flogging.MustGetLogger("test"),
			StepLogger:          flogging.MustGetLogger("test"),
			MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
			RequestHandler:      handler,
		}

		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nodeConsensusRequest, nil).Once()
		err := svc.Step(stream)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = access denied")
	})

	t.Run("Client closes the stream prematurely", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		handler := &mocks.Handler{}

		svc := &cluster.ClusterService{
			StreamCountReporter: &cluster.StreamCountReporter{
				Metrics: cluster.NewMetrics(&disabled.Provider{}),
			},
			Logger:              flogging.MustGetLogger("test"),
			StepLogger:          flogging.MustGetLogger("test"),
			MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
			RequestHandler:      handler,
		}

		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nil, io.EOF).Once()
		err := svc.Step(stream)
		require.NoError(t, err)
	})

	t.Run("Connection terminated with error prematurely", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		handler := &mocks.Handler{}

		svc := &cluster.ClusterService{
			StreamCountReporter: &cluster.StreamCountReporter{
				Metrics: cluster.NewMetrics(&disabled.Provider{}),
			},
			Logger:              flogging.MustGetLogger("test"),
			StepLogger:          flogging.MustGetLogger("test"),
			MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
			RequestHandler:      handler,
		}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nil, errors.New("oops")).Once()
		err := svc.Step(stream)
		require.EqualError(t, err, "oops")
	})

	t.Run("Invalid request type fails with error", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		handler := &mocks.Handler{}

		server, stepStream := createClusterService(t)
		defer server.Stop()

		svc := &cluster.ClusterService{
			StreamCountReporter: &cluster.StreamCountReporter{
				Metrics: cluster.NewMetrics(&disabled.Provider{}),
			},
			Logger:              flogging.MustGetLogger("test"),
			StepLogger:          flogging.MustGetLogger("test"),
			MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
			RequestHandler:      handler,
		}

		stream.On("Context").Return(stepStream.Context())
		stream.On("Recv").Return(nodeAuthrequest, nil).Once()
		stream.On("Recv").Return(nodeInvalidRequest, nil).Once()
		stream.On("Recv").Return(nil, io.EOF).Once()

		bindingHash := cluster.GetSessionBindingHash(authRequest)
		authRequest.SessionBinding, _ = cluster.GetTLSSessionBinding(stepStream.Context(), bindingHash)

		asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
			Version:   int64(authRequest.Version),
			Timestamp: authRequest.Timestamp.String(),
			FromId:    strconv.FormatUint(authRequest.FromId, 10),
			ToId:      strconv.FormatUint(authRequest.ToId, 10),
			Channel:   authRequest.Channel,
		})

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		signer := signingIdentity{clientKeyPair1.Signer}
		sig, err := signer.Sign(asnSignFields)
		require.NoError(t, err)

		authRequest.Signature = sig
		svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})
		err = svc.Step(stream)
		require.EqualError(t, err, "Message is neither a Submit nor Consensus request")
	})
}

func TestClusterServiceVerifyAuthRequest(t *testing.T) {
	handler := &mocks.Handler{}

	svc := &cluster.ClusterService{
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: cluster.NewMetrics(&disabled.Provider{}),
		},
		Logger:              flogging.MustGetLogger("test"),
		StepLogger:          flogging.MustGetLogger("test"),
		MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
		RequestHandler:      handler,
	}

	t.Run("Verify auth request completes successfully", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}

		server, stepStream := createClusterService(t)
		defer server.Stop()

		stream.On("Context").Return(stepStream.Context())
		bindingHash := cluster.GetSessionBindingHash(authRequest)
		authRequest.SessionBinding, _ = cluster.GetTLSSessionBinding(stepStream.Context(), bindingHash)

		asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
			Version:   int64(authRequest.Version),
			Timestamp: authRequest.Timestamp.String(),
			FromId:    strconv.FormatUint(authRequest.FromId, 10),
			ToId:      strconv.FormatUint(authRequest.ToId, 10),
			Channel:   authRequest.Channel,
		})

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		signer := signingIdentity{clientKeyPair1.Signer}
		sig, err := signer.Sign(asnSignFields)
		require.NoError(t, err)

		authRequest.Signature = sig
		svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})
		_, _, err = svc.VerifyAuthRequest(stream, nodeAuthrequest)
		require.NoError(t, err)
	})

	t.Run("Verify auth request fails with sessing binding error", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})

		_, _, err := svc.VerifyAuthRequest(stream, nodeAuthrequest)

		require.EqualError(t, err, "session binding read failed: failed extracting stream context")
	})

	t.Run("Verify auth request fails with session binding mismatch", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		server, stepStream := createClusterService(t)
		defer server.Stop()

		stream.On("Context").Return(stepStream.Context())
		authRequest.SessionBinding = []byte{}
		asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
			Version:   int64(authRequest.Version),
			Timestamp: authRequest.Timestamp.String(),
			FromId:    strconv.FormatUint(authRequest.FromId, 10),
			ToId:      strconv.FormatUint(authRequest.ToId, 10),
			Channel:   authRequest.Channel,
		})

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		signer := signingIdentity{clientKeyPair1.Signer}
		sig, err := signer.Sign(asnSignFields)
		require.NoError(t, err)

		authRequest.Signature = sig
		svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})

		_, _, err = svc.VerifyAuthRequest(stream, nodeAuthrequest)
		require.EqualError(t, err, "session binding mismatch")
	})

	t.Run("Verify auth request fails with channel config not found", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		server, stepStream := createClusterService(t)
		defer server.Stop()

		stream.On("Context").Return(stepStream.Context())
		bindingHash := cluster.GetSessionBindingHash(authRequest)
		authRequest.SessionBinding, _ = cluster.GetTLSSessionBinding(stepStream.Context(), bindingHash)
		asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
			Version:   int64(authRequest.Version),
			Timestamp: authRequest.Timestamp.String(),
			FromId:    strconv.FormatUint(authRequest.FromId, 10),
			ToId:      strconv.FormatUint(authRequest.ToId, 10),
			Channel:   authRequest.Channel,
		})

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		signer := signingIdentity{clientKeyPair1.Signer}
		sig, err := signer.Sign(asnSignFields)
		require.NoError(t, err)

		authRequest.Signature = sig

		delete(svc.MembershipByChannel, authRequest.Channel)

		_, _, err = svc.VerifyAuthRequest(stream, nodeAuthrequest)
		require.EqualError(t, err, "channel mychannel not found in config")
	})

	t.Run("Verify auth request fails with node not part of the channel", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		server, stepStream := createClusterService(t)
		defer server.Stop()

		stream.On("Context").Return(stepStream.Context())
		bindingHash := cluster.GetSessionBindingHash(authRequest)
		authRequest.SessionBinding, _ = cluster.GetTLSSessionBinding(stepStream.Context(), bindingHash)
		asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
			Version:   int64(authRequest.Version),
			Timestamp: authRequest.Timestamp.String(),
			FromId:    strconv.FormatUint(authRequest.FromId, 10),
			ToId:      strconv.FormatUint(authRequest.ToId, 10),
			Channel:   authRequest.Channel,
		})

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		signer := signingIdentity{clientKeyPair1.Signer}
		sig, err := signer.Sign(asnSignFields)
		require.NoError(t, err)

		authRequest.Signature = sig

		delete(svc.MembershipByChannel, authRequest.Channel)
		svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.ToId), Identity: clientKeyPair1.Cert}})

		_, _, err = svc.VerifyAuthRequest(stream, nodeAuthrequest)
		require.EqualError(t, err, "node 1 is not member of channel mychannel")
	})

	t.Run("Verify auth request fails with signature mismatch", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}

		server, stepStream := createClusterService(t)
		defer server.Stop()

		stream.On("Context").Return(stepStream.Context())
		bindingHash := cluster.GetSessionBindingHash(authRequest)
		authRequest.SessionBinding, _ = cluster.GetTLSSessionBinding(stepStream.Context(), bindingHash)

		asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
			Version:   int64(authRequest.Version),
			Timestamp: authRequest.Timestamp.String(),
			FromId:    strconv.FormatUint(authRequest.FromId, 10),
			ToId:      strconv.FormatUint(authRequest.ToId, 10),
			Channel:   authRequest.Channel,
		})

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		signer := signingIdentity{clientKeyPair1.Signer}
		sig, err := signer.Sign(asnSignFields)
		require.NoError(t, err)

		authRequest.Signature = sig

		clientKeyPair2, _ := ca.NewClientCertKeyPair()
		svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair2.Cert}})
		_, _, err = svc.VerifyAuthRequest(stream, nodeAuthrequest)
		require.EqualError(t, err, "signature mismatch: signature invalid")
	})
}

func TestConfigureNodeCerts(t *testing.T) {
	svc := &cluster.ClusterService{}
	t.Run("Throws error when storage not initialized", func(t *testing.T) {
		err := svc.ConfigureNodeCerts("mychannel", nil)
		require.EqualError(t, err, "Nodes cert storage is not initialized")
	})

	t.Run("Creates new entry when input channel not part of the members list", func(t *testing.T) {
		svc.Logger = flogging.MustGetLogger("test")
		svc.MembershipByChannel = make(map[string]*cluster.ChannelMembersConfig)

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		err := svc.ConfigureNodeCerts("mychannel", []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})
		require.NoError(t, err)
		require.Equal(t, clientKeyPair1.Cert, svc.MembershipByChannel["mychannel"].MemberMapping[authRequest.FromId])
	})

	t.Run("Updates entries when existing channel members provided", func(t *testing.T) {
		svc.Logger = flogging.MustGetLogger("test")
		svc.MembershipByChannel = make(map[string]*cluster.ChannelMembersConfig)

		clientKeyPair1, _ := ca.NewClientCertKeyPair()
		err := svc.ConfigureNodeCerts("mychannel", []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})
		require.NoError(t, err)
		require.Equal(t, clientKeyPair1.Cert, svc.MembershipByChannel["mychannel"].MemberMapping[authRequest.FromId])

		err = svc.ConfigureNodeCerts("mychannel", []common.Consenter{{Id: uint32(authRequest.FromId)}})
		require.NoError(t, err)
		require.Equal(t, []byte(nil), svc.MembershipByChannel["mychannel"].MemberMapping[authRequest.FromId])
	})
}

func TestExpirationWarning(t *testing.T) {
	server, stepStream := createClusterService(t)
	defer server.Stop()

	handler := &mocks.Handler{}
	stream := &mocks.ClusterStepStream{}

	cert := util.ExtractCertificateFromContext(stepStream.Context())

	svc := &cluster.ClusterService{
		CertExpWarningThreshold:          time.Until(cert.NotAfter),
		MinimumExpirationWarningInterval: time.Second * 2,
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: cluster.NewMetrics(&disabled.Provider{}),
		},
		Logger:              flogging.MustGetLogger("test"),
		StepLogger:          flogging.MustGetLogger("test"),
		RequestHandler:      handler,
		MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
	}

	stream.On("Context").Return(stepStream.Context())
	stream.On("Recv").Return(nodeAuthrequest, nil).Once()
	stream.On("Recv").Return(nodeConsensusRequest, nil).Once()
	stream.On("Recv").Return(nil, io.EOF).Once()

	bindingHash := cluster.GetSessionBindingHash(authRequest)
	authRequest.SessionBinding, _ = cluster.GetTLSSessionBinding(stepStream.Context(), bindingHash)

	asnSignFields, _ := asn1.Marshal(cluster.AuthRequestSignature{
		Version:   int64(authRequest.Version),
		Timestamp: authRequest.Timestamp.String(),
		FromId:    strconv.FormatUint(authRequest.FromId, 10),
		ToId:      strconv.FormatUint(authRequest.ToId, 10),
		Channel:   authRequest.Channel,
	})

	clientKeyPair1, _ := ca.NewClientCertKeyPair()
	signer := signingIdentity{clientKeyPair1.Signer}
	sig, err := signer.Sign(asnSignFields)
	require.NoError(t, err)

	authRequest.Signature = sig

	handler.On("OnConsensus", authRequest.Channel, authRequest.FromId, mock.Anything).Return(nil).Once()

	svc.ConfigureNodeCerts(authRequest.Channel, []common.Consenter{{Id: uint32(authRequest.FromId), Identity: clientKeyPair1.Cert}})

	alerts := make(chan struct{}, 10)
	svc.Logger = svc.Logger.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
		if strings.Contains(entry.Message, "expires in less than") {
			alerts <- struct{}{}
		}
		return nil
	}))

	_ = svc.Step(stream)

	// An alert is logged at the first time.
	select {
	case <-alerts:
	case <-time.After(time.Second * 5):
		t.Fatal("Should have received an alert")
	}
}

func TestClusterRequestAsString(t *testing.T) {
	t.Run("when input arg is nil returns error string", func(t *testing.T) {
		retVal := cluster.ClusterRequestAsString(nil)
		require.Equal(t, "Request is nil", retVal)
	})

	t.Run("when input arg is unknown type returns error string", func(t *testing.T) {
		retVal := cluster.ClusterRequestAsString(nodeAuthrequest)
		require.Contains(t, retVal, "unknown type:")
	})

	t.Run("when valid input arg is sent returns formatted string", func(t *testing.T) {
		retVal := cluster.ClusterRequestAsString(nodeConsensusRequest)
		require.Contains(t, retVal, "ConsensusRequest for channel")
	})
}
