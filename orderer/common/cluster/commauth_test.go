/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cluster_test

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/crypto"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/metrics"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	comm_utils "github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/cluster/mocks"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type clusterAuthServer interface {
	// Step passes an implementation-specific message to another cluster member.
	Step(server orderer.ClusterNodeService_StepServer) error
}

type clusterServiceNode struct {
	dialer       *cluster.PredicateDialer
	handler      *mocks.Handler
	nodeInfo     cluster.RemoteNode
	srv          *comm_utils.GRPCServer
	bindAddress  string
	clientConfig comm_utils.ClientConfig
	serverConfig comm_utils.ServerConfig
	c            *cluster.Comm
	dispatcher   clusterAuthServer
}

func (cn *clusterServiceNode) Step(stream orderer.ClusterNodeService_StepServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	if err == io.EOF {
		return nil
	}

	i := rand.Int()
	fmt.Println("Step function with execution id: ", i)

	var channel string
	if authReq := req.GetNodeAuthrequest(); authReq != nil {
		fmt.Println("Auth request for channel: ", authReq.Channel, "with execution id", i)
		channel = authReq.Channel
		stream.Send(&orderer.ClusterNodeServiceStepResponse{
			Payload: &orderer.ClusterNodeServiceStepResponse_TranorderRes{
				TranorderRes: &orderer.TransactionOrderResponse{
					Channel: authReq.Channel,
					Status:  common.Status_SUCCESS,
				},
			},
		})
		req, err = stream.Recv()
		if err != nil {
			return err
		}
		if err == io.EOF {
			return nil
		}
	}

	fmt.Println("Tran/Consensus request for channel: ", channel, "with execution id", i)

	if submitReq := req.GetNodeTranrequest(); submitReq != nil {
		submitStepReq := &orderer.SubmitRequest{
			Channel:           channel,
			LastValidationSeq: submitReq.LastValidationSeq,
			Payload:           submitReq.Payload,
		}
		return cn.c.DispatchSubmit(stream.Context(), submitStepReq)
	}
	if conReq := req.GetNodeConrequest(); conReq != nil {
		conStepReq := &orderer.ConsensusRequest{
			Channel:  channel,
			Payload:  conReq.Payload,
			Metadata: conReq.Metadata,
		}
		if err := cn.c.DispatchConsensus(stream.Context(), conStepReq); err != nil {
			return err
		}
	}

	return stream.Send(&orderer.ClusterNodeServiceStepResponse{})
}

func (cn *clusterServiceNode) stop() {
	cn.srv.Stop()
	cn.c.Shutdown()
}

func (cn *clusterServiceNode) resurrect() {
	gRPCServer, err := comm_utils.NewGRPCServer(cn.bindAddress, cn.serverConfig)
	if err != nil {
		panic(fmt.Errorf("failed starting gRPC server: %v", err))
	}
	cn.srv = gRPCServer
	orderer.RegisterClusterNodeServiceServer(gRPCServer.Server(), cn.dispatcher)
	go cn.srv.Start()
}

func newClusterNodeWithMetrics(t *testing.T, metrics cluster.MetricsProvider, tlsConnGauge metrics.Gauge) *clusterServiceNode {
	serverKeyPair, err := ca.NewServerCertKeyPair("127.0.0.1")
	require.NoError(t, err)

	clientKeyPair, _ := ca.NewClientCertKeyPair()

	handler := &mocks.Handler{}
	clientConfig := comm_utils.ClientConfig{
		AsyncConnect: true,
		DialTimeout:  time.Hour,
		SecOpts: comm_utils.SecureOptions{
			RequireClientCert: true,
			Key:               clientKeyPair.Key,
			Certificate:       clientKeyPair.Cert,
			ServerRootCAs:     [][]byte{ca.CertBytes()},
			UseTLS:            true,
			ClientRootCAs:     [][]byte{ca.CertBytes()},
		},
	}

	dialer := &cluster.PredicateDialer{
		Config: clientConfig,
	}

	srvConfig := comm_utils.ServerConfig{
		SecOpts: comm_utils.SecureOptions{
			Key:         serverKeyPair.Key,
			Certificate: serverKeyPair.Cert,
			UseTLS:      true,
		},
	}
	gRPCServer, err := comm_utils.NewGRPCServer("127.0.0.1:", srvConfig)
	require.NoError(t, err)

	tstSrv := &clusterServiceNode{
		dialer:       dialer,
		clientConfig: clientConfig,
		serverConfig: srvConfig,
		bindAddress:  gRPCServer.Address(),
		handler:      handler,
		nodeInfo: cluster.RemoteNode{
			Endpoint:      gRPCServer.Address(),
			ID:            nextUnusedID(),
			ServerTLSCert: serverKeyPair.TLSCert.Raw,
			ClientTLSCert: clientKeyPair.TLSCert.Raw,
		},
		srv: gRPCServer,
	}

	compareCert := cluster.CachePublicKeyComparisons(func(a, b []byte) bool {
		return crypto.CertificatesWithSamePublicKey(a, b) == nil
	})

	if tstSrv.dispatcher == nil {
		tstSrv.dispatcher = tstSrv
	}

	tstSrv.c = &cluster.Comm{
		CertExpWarningThreshold: time.Hour,
		SendBufferSize:          1,
		Logger:                  flogging.MustGetLogger("test"),
		Chan2Members:            make(cluster.MembersByChannel),
		H:                       handler,
		ChanExt:                 channelExtractor,
		Connections:             cluster.NewConnectionStore(dialer, tlsConnGauge),
		Metrics:                 cluster.NewMetrics(metrics),
		CompareCertificate:      compareCert,
		ServiceClientVersion:    cluster.ClusterServiceClientWithAuth,
	}

	orderer.RegisterClusterNodeServiceServer(gRPCServer.Server(), tstSrv.dispatcher)
	go gRPCServer.Start()
	return tstSrv
}

func newTestNodeWithAuthentication(t *testing.T) *clusterServiceNode {
	return newClusterNodeWithMetrics(t, &disabled.Provider{}, &disabled.Gauge{})
}

func TestCommServiceBasicAuth(t *testing.T) {
	// Scenario: Basic test that spawns 2 nodes and sends each other
	// messages that are expected to be echoed back

	node1 := newTestNodeWithAuthentication(t)
	node2 := newTestNodeWithAuthentication(t)

	defer node1.stop()
	defer node2.stop()

	config := []cluster.RemoteNode{node1.nodeInfo, node2.nodeInfo}
	node1.c.Configure(testChannel, config)
	node2.c.Configure(testChannel, config)

	assertBiDiCommunicationForChannelWitSigner(t, node1, node2, testReq, testChannel, &mocks.SignerSerializer{})
}

func TestCommServiceMultiChannelAuth(t *testing.T) {
	// Scenario: node 1 knows node 2 only in channel "foo"
	// and knows node 3 only in channel "bar".
	// Messages that are received, are routed according to their corresponding channels

	node1 := newTestNodeWithAuthentication(t)
	node2 := newTestNodeWithAuthentication(t)
	node3 := newTestNodeWithAuthentication(t)

	defer node1.stop()
	defer node2.stop()
	defer node3.stop()

	node1.c.Configure("foo", []cluster.RemoteNode{node2.nodeInfo})
	node1.c.Configure("bar", []cluster.RemoteNode{node3.nodeInfo})
	node2.c.Configure("foo", []cluster.RemoteNode{node1.nodeInfo})
	node3.c.Configure("bar", []cluster.RemoteNode{node1.nodeInfo})

	t.Run("Correct channel", func(t *testing.T) {
		var fromNode2 sync.WaitGroup
		fromNode2.Add(1)
		node1.handler.On("OnSubmit", "foo", node2.nodeInfo.ID, mock.Anything).Return(nil).Run(func(_ mock.Arguments) {
			fromNode2.Done()
		}).Once()

		var fromNode3 sync.WaitGroup
		fromNode3.Add(1)
		node1.handler.On("OnSubmit", "bar", node3.nodeInfo.ID, mock.Anything).Return(nil).Run(func(_ mock.Arguments) {
			fromNode3.Done()
		}).Once()

		node2toNode1, err := node2.c.Remote("foo", node1.nodeInfo.ID)
		require.NoError(t, err)
		node3toNode1, err := node3.c.Remote("bar", node1.nodeInfo.ID)
		require.NoError(t, err)

		stream := assertEventualEstablishStreamWithSigner(t, node2toNode1, &mocks.SignerSerializer{})
		stream.Send(fooReq)

		fromNode2.Wait()
		node1.handler.AssertNumberOfCalls(t, "OnSubmit", 1)

		stream = assertEventualEstablishStreamWithSigner(t, node3toNode1, &mocks.SignerSerializer{})
		stream.Send(barReq)

		fromNode3.Wait()
		node1.handler.AssertNumberOfCalls(t, "OnSubmit", 2)
	})
}

func TestCommServiceReconnectAuth(t *testing.T) {
	// Scenario: node 1 and node 2 are connected,
	// and node 2 is taken offline.
	// Node 1 tries to send a message to node 2 but fails,
	// and afterwards node 2 is brought back, after which
	// node 1 sends more messages, and it should succeed
	// sending a message to node 2 eventually.

	node1 := newTestNodeWithAuthentication(t)
	defer node1.stop()
	conf := node1.dialer.Config
	conf.DialTimeout = time.Hour

	node2 := newTestNodeWithAuthentication(t)
	node2.handler.On("OnSubmit", testChannel, node1.nodeInfo.ID, mock.Anything).Return(nil)
	defer node2.stop()

	config := []cluster.RemoteNode{node1.nodeInfo, node2.nodeInfo}
	node1.c.Configure(testChannel, config)
	node2.c.Configure(testChannel, config)

	// Make node 2 be offline by shutting down its gRPC service
	node2.srv.Stop()
	// Obtain the stub for node 2.
	// Should succeed, because the connection was created at time of configuration
	stub, err := node1.c.Remote(testChannel, node2.nodeInfo.ID)
	require.NoError(t, err)

	// Try to obtain a stream. Should not Succeed.
	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() error {
		_, err = stub.NewStream(time.Hour, &mocks.SignerSerializer{})
		return err
	}).Should(gomega.Not(gomega.Succeed()))

	// Wait for the port to be released
	for {
		lsnr, err := net.Listen("tcp", node2.nodeInfo.Endpoint)
		if err == nil {
			lsnr.Close()
			break
		}
	}

	// Resurrect node 2
	node2.resurrect()
	// Send a message from node 1 to node 2.
	// Should succeed eventually
	assertEventualSendMessageWithSigner(t, stub, testReq, &mocks.SignerSerializer{})
}

func TestCommServiceMembershipReconfigurationAuth(t *testing.T) {
	// Scenario: node 1 and node 2 are started up
	// and node 2 is configured to know about node 1,
	// without node1 knowing about node 2.
	// The communication between them should only work
	// after node 1 is configured to know about node 2.

	node1 := newTestNodeWithAuthentication(t)
	defer node1.stop()

	node2 := newTestNodeWithAuthentication(t)
	defer node2.stop()

	node1.c.Configure(testChannel, []cluster.RemoteNode{})
	node2.c.Configure(testChannel, []cluster.RemoteNode{node1.nodeInfo})

	// Node 1 can't connect to node 2 because it doesn't know its TLS certificate yet
	_, err := node1.c.Remote(testChannel, node2.nodeInfo.ID)
	require.EqualError(t, err, fmt.Sprintf("node %d doesn't exist in channel test's membership", node2.nodeInfo.ID))
	// Node 2 can connect to node 1, but it can't send it messages because node 1 doesn't know node 2 yet.

	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() (bool, error) {
		_, err := node2.c.Remote(testChannel, node1.nodeInfo.ID)
		return true, err
	}, time.Minute).Should(gomega.BeTrue())

	stub, err := node2.c.Remote(testChannel, node1.nodeInfo.ID)
	require.NoError(t, err)

	stream := assertEventualEstablishStreamWithSigner(t, stub, &mocks.SignerSerializer{})
	err = stream.Send(wrapSubmitReq(testSubReq))
	require.NoError(t, err)

	_, err = stream.Recv()
	require.EqualError(t, err, "rpc error: code = Unknown desc = certificate extracted from TLS connection isn't authorized")

	// Next, configure node 1 to know about node 2
	node1.c.Configure(testChannel, []cluster.RemoteNode{node2.nodeInfo})

	// Check that the communication works correctly between both nodes
	assertBiDiCommunicationForChannelWitSigner(t, node1, node2, testReq, testChannel, &mocks.SignerSerializer{})
	assertBiDiCommunicationForChannelWitSigner(t, node2, node1, testReq, testChannel, &mocks.SignerSerializer{})

	// Reconfigure node 2 to forget about node 1
	node2.c.Configure(testChannel, []cluster.RemoteNode{})
	// Node 1 can still connect to node 2
	stub, err = node1.c.Remote(testChannel, node2.nodeInfo.ID)
	require.NoError(t, err)
	// But can't send a message because node 2 now doesn't authorized node 1
	stream = assertEventualEstablishStreamWithSigner(t, stub, &mocks.SignerSerializer{})
	stream.Send(wrapSubmitReq(testSubReq))
	_, err = stream.Recv()
	require.EqualError(t, err, "rpc error: code = Unknown desc = certificate extracted from TLS connection isn't authorized")
}

func assertEventualEstablishStreamWithSigner(t *testing.T, rpc *cluster.RemoteContext, signer identity.SignerSerializer) *cluster.Stream {
	var res *cluster.Stream
	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() error {
		stream, err := rpc.NewStream(time.Hour, signer)
		res = stream
		return err
	}, timeout).Should(gomega.Succeed())
	return res
}

func assertEventualSendMessageWithSigner(t *testing.T, rpc *cluster.RemoteContext, req *orderer.SubmitRequest, signer identity.SignerSerializer) *cluster.Stream {
	var res *cluster.Stream
	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() error {
		stream, err := rpc.NewStream(time.Hour, signer)
		if err != nil {
			return err
		}
		res = stream
		return stream.Send(wrapSubmitReq(req))
	}, timeout).Should(gomega.Succeed())
	return res
}

func assertBiDiCommunicationForChannelWitSigner(t *testing.T, node1, node2 *clusterServiceNode, msgToSend *orderer.SubmitRequest, channel string, signer identity.SignerSerializer) {
	establish := []struct {
		label    string
		sender   *clusterServiceNode
		receiver *clusterServiceNode
		target   uint64
	}{
		{label: "1->2", sender: node1, target: node2.nodeInfo.ID, receiver: node2},
		{label: "2->1", sender: node2, target: node1.nodeInfo.ID, receiver: node1},
	}
	for _, estab := range establish {
		stub, err := estab.sender.c.Remote(channel, estab.target)
		require.NoError(t, err)

		stream := assertEventualEstablishStreamWithSigner(t, stub, signer)

		var wg sync.WaitGroup
		wg.Add(1)
		estab.receiver.handler.On("OnSubmit", channel, estab.sender.nodeInfo.ID, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			req := args.Get(2).(*orderer.SubmitRequest)
			require.True(t, proto.Equal(req, msgToSend))
			t.Log(estab.label)
			wg.Done()
		})

		err = stream.Send(wrapSubmitReq(msgToSend))
		require.NoError(t, err)

		wg.Wait()
	}
}
