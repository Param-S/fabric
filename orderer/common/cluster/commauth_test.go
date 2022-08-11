/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cluster_test

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-protos-go/common"
	"github.com/hyperledger/fabric-protos-go/orderer"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/metrics/disabled"
	comm_utils "github.com/hyperledger/fabric/internal/pkg/comm"
	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/orderer/common/cluster"
	"github.com/hyperledger/fabric/orderer/common/cluster/mocks"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type clusterServiceNode struct {
	nodeInfo     cluster.NodeAddress
	bindAddress  string
	server       *comm_utils.GRPCServer
	cli          *cluster.AuthCommMgr
	service      *cluster.ClusterService
	handler      *mocks.Handler
	serverConfig comm_utils.ServerConfig
}

func (csn *clusterServiceNode) resurrect() {
	gRPCServer, err := comm_utils.NewGRPCServer(csn.bindAddress, csn.serverConfig)
	if err != nil {
		panic(fmt.Errorf("failed starting gRPC server: %v", err))
	}
	csn.server = gRPCServer
	orderer.RegisterClusterNodeServiceServer(gRPCServer.Server(), csn.service)
	go csn.server.Start()
}

type signingIdentity struct {
	crypto.Signer
}

func (si *signingIdentity) Sign(msg []byte) ([]byte, error) {
	return si.Signer.Sign(rand.Reader, msg, nil)
}

func newClusterServiceNode(t *testing.T, signer identity.Signer) *clusterServiceNode {
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

	handler := &mocks.Handler{}

	tstSrv := &cluster.ClusterService{
		StreamCountReporter: &cluster.StreamCountReporter{
			Metrics: cluster.NewMetrics(&disabled.Provider{}),
		},
		Logger:              flogging.MustGetLogger("test"),
		StepLogger:          flogging.MustGetLogger("test"),
		RequestHandler:      handler,
		MembershipByChannel: make(map[string]*cluster.ChannelMembersConfig),
	}

	orderer.RegisterClusterNodeServiceServer(gRPCServer.Server(), tstSrv)
	go gRPCServer.Start()

	clientConfig := comm_utils.ClientConfig{
		AsyncConnect: true,
		DialTimeout:  time.Hour,
		SecOpts: comm_utils.SecureOptions{
			ServerRootCAs: [][]byte{ca.CertBytes()},
			UseTLS:        true,
			ClientRootCAs: [][]byte{ca.CertBytes()},
		},
	}

	cli := &cluster.AuthCommMgr{
		SendBufferSize: 1,
		Logger:         flogging.MustGetLogger("test"),
		Chan2Members:   make(cluster.MembersByChannel),
		Connections:    cluster.NewConnectionMgr(clientConfig),
		Metrics:        cluster.NewMetrics(&disabled.Provider{}),
		Signer:         signer,
		NodeID:         nextUnusedID(),
	}

	node := &clusterServiceNode{
		server:  gRPCServer,
		service: tstSrv,
		cli:     cli,
		nodeInfo: cluster.NodeAddress{
			Endpoint: gRPCServer.Address(),
			ID:       cli.NodeID,
		},
		handler:      handler,
		serverConfig: srvConfig,
		bindAddress:  gRPCServer.Address(),
	}

	return node
}

func TestCommServiceBasicAuthentication(t *testing.T) {
	// Scenario: Basic test that spawns 2 nodes and sends each other
	// messages that are expected to be echoed back

	clientKeyPair1, _ := ca.NewClientCertKeyPair()
	node1 := newClusterServiceNode(t, &signingIdentity{clientKeyPair1.Signer})
	defer node1.server.Stop()
	defer node1.cli.Shutdown()

	clientKeyPair2, _ := ca.NewClientCertKeyPair()
	node2 := newClusterServiceNode(t, &signingIdentity{clientKeyPair2.Signer})
	defer node2.server.Stop()
	defer node2.cli.Shutdown()

	config := []cluster.NodeAddress{node1.nodeInfo, node2.nodeInfo}
	node1.cli.Configure(testChannel, config)
	node2.cli.Configure(testChannel, config)

	node1.service.ConfigureNodeCerts(testChannel, []common.Consenter{{Id: uint32(node2.nodeInfo.ID), Identity: clientKeyPair2.Cert}})
	node2.service.ConfigureNodeCerts(testChannel, []common.Consenter{{Id: uint32(node1.nodeInfo.ID), Identity: clientKeyPair1.Cert}})

	assertBiDiCommunicationForChannelWithSigner(t, node1, node2, testReq, testChannel)
}

func TestCommServiceMultiChannelAuth(t *testing.T) {
	// Scenario: node 1 knows node 2 only in channel "foo"
	// and knows node 3 only in channel "bar".
	// Messages that are received, are routed according to their corresponding channels

	clientKeyPair1, _ := ca.NewClientCertKeyPair()
	node1 := newClusterServiceNode(t, &signingIdentity{clientKeyPair1.Signer})
	clientKeyPair2, _ := ca.NewClientCertKeyPair()
	node2 := newClusterServiceNode(t, &signingIdentity{clientKeyPair2.Signer})
	clientKeyPair3, _ := ca.NewClientCertKeyPair()
	node3 := newClusterServiceNode(t, &signingIdentity{clientKeyPair3.Signer})

	defer node1.server.Stop()
	defer node2.server.Stop()
	defer node3.server.Stop()
	defer node1.cli.Shutdown()
	defer node2.cli.Shutdown()
	defer node3.cli.Shutdown()

	node1.cli.Configure("foo", []cluster.NodeAddress{node2.nodeInfo})
	node1.cli.Configure("bar", []cluster.NodeAddress{node3.nodeInfo})
	node2.cli.Configure("foo", []cluster.NodeAddress{node1.nodeInfo})
	node3.cli.Configure("bar", []cluster.NodeAddress{node1.nodeInfo})

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

		node1.service.ConfigureNodeCerts("foo", []common.Consenter{{Id: uint32(node2.nodeInfo.ID), Identity: clientKeyPair2.Cert}})
		node1.service.ConfigureNodeCerts("bar", []common.Consenter{{Id: uint32(node3.nodeInfo.ID), Identity: clientKeyPair3.Cert}})

		node2toNode1, err := node2.cli.Remote("foo", node1.nodeInfo.ID)
		require.NoError(t, err)

		node2toNode1.SourceNodeID = node2.nodeInfo.ID
		node2toNode1.DestinationNodeID = node1.nodeInfo.ID

		node3toNode1, err := node3.cli.Remote("bar", node1.nodeInfo.ID)
		require.NoError(t, err)

		node3toNode1.SourceNodeID = node3.nodeInfo.ID
		node3toNode1.DestinationNodeID = node1.nodeInfo.ID

		stream := assertEventualEstablishStreamWithSigner(t, node2toNode1)
		stream.Send(fooReq)

		fromNode2.Wait()
		node1.handler.AssertNumberOfCalls(t, "OnSubmit", 1)

		stream = assertEventualEstablishStreamWithSigner(t, node3toNode1)
		stream.Send(barReq)

		fromNode3.Wait()
		node1.handler.AssertNumberOfCalls(t, "OnSubmit", 2)
	})
}

func TestCommServiceMembershipReconfigurationAuth(t *testing.T) {
	// Scenario: node 1 and node 2 are started up
	// and node 2 is configured to know about node 1,
	// without node1 knowing about node 2.
	// The communication between them should only work
	// after node 1 is configured to know about node 2.

	clientKeyPair1, _ := ca.NewClientCertKeyPair()
	node1 := newClusterServiceNode(t, &signingIdentity{clientKeyPair1.Signer})
	clientKeyPair2, _ := ca.NewClientCertKeyPair()
	node2 := newClusterServiceNode(t, &signingIdentity{clientKeyPair2.Signer})

	defer node1.server.Stop()
	defer node2.server.Stop()

	defer node1.cli.Shutdown()
	defer node2.cli.Shutdown()

	node1.cli.Configure(testChannel, []cluster.NodeAddress{})
	node2.cli.Configure(testChannel, []cluster.NodeAddress{node1.nodeInfo})

	// Node 1 can't connect to node 2 because it doesn't know its TLS certificate yet
	_, err := node1.cli.Remote(testChannel, node2.nodeInfo.ID)
	require.EqualError(t, err, fmt.Sprintf("node %d doesn't exist in channel test's membership", node2.nodeInfo.ID))

	// Node 2 can connect to node 1, but it can't send it messages because node 1 doesn't know node 2 yet.
	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() (bool, error) {
		_, err := node2.cli.Remote(testChannel, node1.nodeInfo.ID)
		return true, err
	}, time.Minute).Should(gomega.BeTrue())

	stub, err := node2.cli.Remote(testChannel, node1.nodeInfo.ID)
	require.NoError(t, err)

	node2.service.ConfigureNodeCerts(testChannel, []common.Consenter{
		{Id: uint32(node1.nodeInfo.ID), Identity: clientKeyPair1.Cert},
	})

	node1.service.ConfigureNodeCerts(testChannel, []common.Consenter{})

	stream := assertEventualEstablishStreamWithSigner(t, stub)
	err = stream.Send(wrapSubmitReq(testSubReq))
	require.NoError(t, err)

	_, err = stream.Recv()
	require.EqualError(t, err, "rpc error: code = Unauthenticated desc = access denied")

	// Next, configure node 1 to know about node 2
	node1.cli.Configure(testChannel, []cluster.NodeAddress{node2.nodeInfo})

	node1.service.ConfigureNodeCerts(testChannel, []common.Consenter{
		{Id: uint32(node2.nodeInfo.ID), Identity: clientKeyPair2.Cert},
	})

	// Check that the communication works correctly between both nodes
	assertBiDiCommunicationForChannelWithSigner(t, node1, node2, testReq, testChannel)

	// Reconfigure node 2 to forget about node 1
	node2.cli.Configure(testChannel, []cluster.NodeAddress{})
	// Node 1 can still connect to node 2
	stub, err = node1.cli.Remote(testChannel, node2.nodeInfo.ID)
	require.NoError(t, err)

	node2.service.ConfigureNodeCerts(testChannel, []common.Consenter{})
	// But can't send a message because node 2 now doesn't authorized node 1
	stream = assertEventualEstablishStreamWithSigner(t, stub)
	stream.Send(wrapSubmitReq(testSubReq))
	_, err = stream.Recv()
	require.EqualError(t, err, "rpc error: code = Unauthenticated desc = access denied")
}

func TestCommServiceReconnectAuth(t *testing.T) {
	// Scenario: node 1 and node 2 are connected,
	// and node 2 is taken offline.
	// Node 1 tries to send a message to node 2 but fails,
	// and afterwards node 2 is brought back, after which
	// node 1 sends more messages, and it should succeed
	// sending a message to node 2 eventually.

	clientKeyPair1, _ := ca.NewClientCertKeyPair()
	node1 := newClusterServiceNode(t, &signingIdentity{clientKeyPair1.Signer})
	clientKeyPair2, _ := ca.NewClientCertKeyPair()
	node2 := newClusterServiceNode(t, &signingIdentity{clientKeyPair2.Signer})

	defer node1.server.Stop()
	defer node2.server.Stop()

	defer node1.cli.Shutdown()
	defer node2.cli.Shutdown()

	// conf := node1.dialer.Config
	// conf.DialTimeout = time.Hour

	node2.handler.On("OnSubmit", testChannel, node1.nodeInfo.ID, mock.Anything).Return(nil)

	config := []cluster.NodeAddress{node1.nodeInfo, node2.nodeInfo}
	node1.cli.Configure(testChannel, config)
	node2.cli.Configure(testChannel, config)

	// Make node 2 be offline by shutting down its gRPC service
	node2.server.Stop()
	// Obtain the stub for node 2.
	// Should succeed, because the connection was created at time of configuration
	stub, err := node1.cli.Remote(testChannel, node2.nodeInfo.ID)
	require.NoError(t, err)

	// Try to obtain a stream. Should not Succeed.
	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() error {
		_, err = stub.NewStream(time.Hour)
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
	assertEventualSendMessageWithSigner(t, stub, testReq)
}

func assertEventualSendMessageWithSigner(t *testing.T, rpc *cluster.RemoteContext, req *orderer.SubmitRequest) *cluster.Stream {
	var res *cluster.Stream
	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() error {
		stream, err := rpc.NewStream(time.Hour)
		if err != nil {
			return err
		}
		res = stream
		return stream.Send(wrapSubmitReq(req))
	}, timeout).Should(gomega.Succeed())
	return res
}

func assertEventualEstablishStreamWithSigner(t *testing.T, rpc *cluster.RemoteContext) *cluster.Stream {
	var res *cluster.Stream
	gt := gomega.NewGomegaWithT(t)
	gt.Eventually(func() error {
		stream, err := rpc.NewStream(time.Hour)
		res = stream
		return err
	}, timeout).Should(gomega.Succeed())
	return res
}

func assertBiDiCommunicationForChannelWithSigner(t *testing.T, node1, node2 *clusterServiceNode, msgToSend *orderer.SubmitRequest, channel string) {
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
		stub, err := estab.sender.cli.Remote(channel, estab.target)
		require.NoError(t, err)

		stream := assertEventualEstablishStreamWithSigner(t, stub)

		var wg sync.WaitGroup
		wg.Add(1)

		estab.receiver.handler.On("OnSubmit", channel, estab.sender.nodeInfo.ID, mock.Anything).Return(nil).Once().Run(func(args mock.Arguments) {
			req := args.Get(2).(*orderer.SubmitRequest)
			require.True(t, proto.Equal(req, msgToSend))
			t.Log(estab.label)
			wg.Done()
			debug.PrintStack()
		})

		err = stream.Send(wrapSubmitReq(msgToSend))
		require.NoError(t, err)

		wg.Wait()
	}
}
