/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cluster_test

import (
	"context"
	"crypto/tls"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/msp"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/cluster/mocks"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var (
	nodeAuthrequest = &orderer.ClusterNodeServiceStepRequest{
		Payload: &orderer.ClusterNodeServiceStepRequest_NodeAuthrequest{
			NodeAuthrequest: &orderer.NodeAuthRequest{
				Channel: "mychannel",
			},
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

type AuthVerifier struct {
	cluster.ClusterService
}

func (cs *AuthVerifier) VerifyAuthRequest(orderer.ClusterNodeService_StepServer, *orderer.ClusterNodeServiceStepRequest, cluster.TLSSessionBindingGetter, cluster.SignatureVerifier) (string, error) {
	return "mychannel", nil
}

func TestClusterServiceStep(t *testing.T) {
	dispatcher := &mocks.Dispatcher{}

	svc := &cluster.ClusterService{
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: cluster.NewMetrics(&disabled.Provider{}),
		},
		Logger:     flogging.MustGetLogger("test"),
		StepLogger: flogging.MustGetLogger("test"),
		Dispatcher: dispatcher,
	}

	t.Run("Create authenticated stream successfully", func(t *testing.T) {
		svc.AuthVerifier = &AuthVerifier{}
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nodeAuthrequest, nil).Once()
		stream.On("Recv").Return(nodeConsensusRequest, nil).Once()
		stream.On("Recv").Return(nil, io.EOF).Once()
		dispatcher.On("DispatchConsensus", mock.Anything, consensusRequest.GetConsensusRequest()).Return(nil).Once()
		err := svc.Step(stream)
		require.NoError(t, err)
	})

	t.Run("Fail with error if first request not auth request message type", func(t *testing.T) {
		svc.AuthVerifier = svc
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nodeConsensusRequest, nil).Once()
		err := svc.Step(stream)
		require.EqualError(t, err, "rpc error: code = Unauthenticated desc = access denied")
	})

	t.Run("Client closes the stream prematurely", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nil, io.EOF).Once()
		err := svc.Step(stream)
		require.NoError(t, err)
	})

	t.Run("Connection terminated with error prematurely", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nil, errors.New("oops")).Once()
		err := svc.Step(stream)
		require.EqualError(t, err, "oops")
	})

	t.Run("Invalid request type fails with error", func(t *testing.T) {
		svc.AuthVerifier = &AuthVerifier{}
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nodeAuthrequest, nil).Once()
		stream.On("Recv").Return(nodeInvalidRequest, nil).Once()
		stream.On("Recv").Return(nil, io.EOF).Once()
		dispatcher.On("DispatchConsensus", mock.Anything, consensusRequest.GetConsensusRequest()).Return(nil).Once()
		err := svc.Step(stream)
		require.EqualError(t, err, "Message is neither a Submit nor Consensus request")
	})
}

func TestClusterServiceVerifyAuthRequest(t *testing.T) {
	dispatcher := &mocks.Dispatcher{}

	svc := &cluster.ClusterService{
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: cluster.NewMetrics(&disabled.Provider{}),
		},
		Logger:              flogging.MustGetLogger("test"),
		StepLogger:          flogging.MustGetLogger("test"),
		Dispatcher:          dispatcher,
		MembershipByChannel: make(map[string]map[uint64]*msp.SerializedIdentity),
	}

	t.Run("Verify auth request completes successfully", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		ctx := context.Background()
		ctx = peer.NewContext(ctx, &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{},
			},
		})
		stream.On("Context").Return(ctx)
		svc.MembershipByChannel["mychannel"] = make(map[uint64]*msp.SerializedIdentity)
		svc.MembershipByChannel["mychannel"][0] = &msp.SerializedIdentity{}
		_, err := svc.VerifyAuthRequest(stream, nodeAuthrequest, func(stream grpc.Stream, bindingPayload []byte) ([]byte, error) {
			return []byte{1}, nil
		}, func(pemContent, msgHash, signature []byte) error { return nil })
		require.NoError(t, err)
	})

	t.Run("Verify auth request fails with sessing binding error", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		ctx := context.Background()
		ctx = peer.NewContext(ctx, &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{},
			},
		})
		stream.On("Context").Return(ctx)
		svc.MembershipByChannel["mychannel"] = make(map[uint64]*msp.SerializedIdentity)
		svc.MembershipByChannel["mychannel"][0] = &msp.SerializedIdentity{}
		_, err := svc.VerifyAuthRequest(stream, nodeAuthrequest, func(stream grpc.Stream, bindingPayload []byte) ([]byte, error) {
			return nil, errors.New("binding error")
		}, func(pemContent, msgHash, signature []byte) error { return nil })
		require.EqualError(t, err, "session binding read failed: binding error")
	})

	t.Run("Verify auth request fails when node not part of the channel", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		ctx := context.Background()
		ctx = peer.NewContext(ctx, &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{},
			},
		})
		stream.On("Context").Return(ctx)
		svc.MembershipByChannel["mychannel"] = make(map[uint64]*msp.SerializedIdentity)
		_, err := svc.VerifyAuthRequest(stream, nodeAuthrequest, func(stream grpc.Stream, bindingPayload []byte) ([]byte, error) {
			return []byte{1}, nil
		}, func(pemContent, msgHash, signature []byte) error { return nil })
		require.EqualError(t, err, "node 0 is not member of channel mychannel")
	})

	t.Run("Verify auth request fails when signature mismatches", func(t *testing.T) {
		stream := &mocks.ClusterStepStream{}
		ctx := context.Background()
		ctx = peer.NewContext(ctx, &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{},
			},
		})
		stream.On("Context").Return(ctx)
		svc.MembershipByChannel["mychannel"] = make(map[uint64]*msp.SerializedIdentity)
		svc.MembershipByChannel["mychannel"][0] = &msp.SerializedIdentity{}
		_, err := svc.VerifyAuthRequest(stream, nodeAuthrequest, func(stream grpc.Stream, bindingPayload []byte) ([]byte, error) {
			return []byte{1}, nil
		}, func(identity, msgHash, signature []byte) error { return errors.New("oops") })
		require.EqualError(t, err, "signature mismatch: oops")
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
		svc.MembershipByChannel = make(map[string]map[uint64]*msp.SerializedIdentity)

		nodeIdentity := cluster.NodeIdentity{
			ID:       0,
			Identity: []byte{1, 2, 3, 4, 5},
		}
		sID := &msp.SerializedIdentity{}
		proto.Unmarshal(nodeIdentity.Identity, sID)

		err := svc.ConfigureNodeCerts("mychannel", []cluster.NodeIdentity{nodeIdentity})
		require.NoError(t, err)
		require.Equal(t, sID, svc.MembershipByChannel["mychannel"][0])
	})

	t.Run("Updates entries when existing channel members provided", func(t *testing.T) {
		svc.Logger = flogging.MustGetLogger("test")
		svc.MembershipByChannel = make(map[string]map[uint64]*msp.SerializedIdentity)

		nodeIdentity := cluster.NodeIdentity{
			ID:       0,
			Identity: []byte{1, 2, 3, 4, 5},
		}
		sID := &msp.SerializedIdentity{}
		proto.Unmarshal(nodeIdentity.Identity, sID)

		err := svc.ConfigureNodeCerts("mychannel", []cluster.NodeIdentity{nodeIdentity})
		require.NoError(t, err)
		require.Equal(t, sID, svc.MembershipByChannel["mychannel"][0])

		nodeIdentity.ID = 1
		err = svc.ConfigureNodeCerts("mychannel", []cluster.NodeIdentity{nodeIdentity})
		require.NoError(t, err)
		require.Equal(t, sID, svc.MembershipByChannel["mychannel"][1])
		require.Equal(t, (*msp.SerializedIdentity)(nil), svc.MembershipByChannel["mychannel"][0])
	})
}

func TestHandleSubmit(t *testing.T) {
	dispatcher := &mocks.Dispatcher{}

	svc := &cluster.ClusterService{
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: cluster.NewMetrics(&disabled.Provider{}),
		},
		Logger:     flogging.MustGetLogger("test"),
		StepLogger: flogging.MustGetLogger("test"),
		Dispatcher: dispatcher,
	}

	t.Run("Dispatch the submit request successfully", func(t *testing.T) {
		svc.AuthVerifier = &AuthVerifier{}
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nodeAuthrequest, nil).Once()
		stream.On("Recv").Return(nodeTranRequest, nil).Once()
		stream.On("Recv").Return(nil, io.EOF).Once()
		dispatcher.On("DispatchSubmit", mock.Anything, submitRequest.GetSubmitRequest()).Return(nil).Once()
		err := svc.Step(stream)
		require.NoError(t, err)
	})

	t.Run("Dispatch failed to submit request", func(t *testing.T) {
		svc.AuthVerifier = &AuthVerifier{}
		stream := &mocks.ClusterStepStream{}
		stream.On("Context").Return(context.Background())
		stream.On("Recv").Return(nodeAuthrequest, nil).Once()
		stream.On("Recv").Return(nodeTranRequest, nil).Once()
		stream.On("Recv").Return(nil, io.EOF).Once()
		dispatcher.On("DispatchSubmit", mock.Anything, submitRequest.GetSubmitRequest()).Return(errors.New("submit dispatch failed")).Once()
		err := svc.Step(stream)
		require.EqualError(t, err, "submit dispatch failed")
	})
}

func TestExpirationWarning(t *testing.T) {
	serverCert, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)

	clientCert, err := ca.NewClientCertKeyPair()
	require.NoError(t, err)

	dispatcher := &mocks.Dispatcher{}
	dispatcher.On("DispatchConsensus", mock.Anything, mock.Anything).Return(nil)

	svc := &cluster.ClusterService{
		CertExpWarningThreshold:          time.Until(clientCert.TLSCert.NotAfter),
		MinimumExpirationWarningInterval: time.Second * 2,
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: cluster.NewMetrics(&disabled.Provider{}),
		},
		Logger:              flogging.MustGetLogger("test"),
		StepLogger:          flogging.MustGetLogger("test"),
		Dispatcher:          dispatcher,
		MembershipByChannel: make(map[string]map[uint64]*msp.SerializedIdentity),
	}

	svc.AuthVerifier = &AuthVerifier{}

	alerts := make(chan struct{}, 10)
	svc.Logger = svc.Logger.WithOptions(zap.Hooks(func(entry zapcore.Entry) error {
		if strings.Contains(entry.Message, "expires in less than 23h59m") {
			alerts <- struct{}{}
		}
		return nil
	}))

	srvConf := comm.ServerConfig{
		SecOpts: comm.SecureOptions{
			Certificate:       serverCert.Cert,
			Key:               serverCert.Key,
			UseTLS:            true,
			ClientRootCAs:     [][]byte{ca.CertBytes()},
			RequireClientCert: true,
		},
	}

	srv, err := comm.NewGRPCServer("127.0.0.1:0", srvConf)
	require.NoError(t, err)
	orderer.RegisterClusterNodeServiceServer(srv.Server(), svc)

	go srv.Start()
	defer srv.Stop()

	clientConf := comm.ClientConfig{
		DialTimeout: time.Second * 3,
		SecOpts: comm.SecureOptions{
			ServerRootCAs:     [][]byte{ca.CertBytes()},
			UseTLS:            true,
			Key:               clientCert.Key,
			Certificate:       clientCert.Cert,
			RequireClientCert: true,
		},
	}

	conn, err := clientConf.Dial(srv.Address())
	require.NoError(t, err)

	cl := orderer.NewClusterNodeServiceClient(conn)
	stream, err := cl.Step(context.Background())
	require.NoError(t, err)

	err = stream.Send(nodeAuthrequest)
	require.NoError(t, err)
	err = stream.Send(nodeConsensusRequest)
	require.NoError(t, err)

	// An alert is logged at the first time.
	select {
	case <-alerts:
	case <-time.After(time.Second * 5):
		t.Fatal("Should have received an alert")
	}

	err = stream.Send(nodeConsensusRequest)
	require.NoError(t, err)

	// No alerts in a consecutive time.
	select {
	case <-alerts:
		t.Fatal("Should have not received an alert")
	case <-time.After(time.Millisecond * 500):
	}

	// Wait for alert expiration interval to expire.
	time.Sleep(svc.MinimumExpirationWarningInterval + time.Second)

	err = stream.Send(nodeConsensusRequest)
	require.NoError(t, err)

	// An alert should be logged now after the timeout expired.
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
