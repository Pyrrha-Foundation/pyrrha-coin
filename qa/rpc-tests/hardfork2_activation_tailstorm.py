#!/usr/bin/env python3
# Copyright (c) 2015-2025 The Bitcoin Unlimited developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import test_framework.loginit
import logging
#logging.getLogger().setLevel(logging.INFO)

#
# Test HardFork2 tailstorm activation
#
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.blocktools import *

# Accurately count satoshis
import decimal
decimal.getcontext().prec = 16

waitTime = 30

class TailstormActivationTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2, self.confDict)

    def setup_network(self):
        self.nodes = []
        self.is_network_split = False
        self.nodes.append(start_node(0, self.options.tmpdir, ["-debug=net", "-debug=dag"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-debug=net", "-debug=dag"]))
        interconnect_nodes(self.nodes)

    def setmocktime(self, time):
        for node in self.nodes:
            node.setmocktime(time)

    def setforktime(self, time):
        for node in self.nodes:
            node.set("consensus.fork2Time=" + str(time))


    def run_test(self):

        # Mine some blocks to get utxos etc

        # Generate enough blocks that we can spend some coinbase.
        nBlocks = 101
        self.nodes[0].generate(nBlocks-1)
        self.sync_all()
        self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 101)

        # mine a few blocks 1 second apart so we can get a more meaningful "mediantime"
        bestblock = self.nodes[0].getbestblockhash()
        lastblocktime = self.nodes[0].getblockheader(bestblock)['time']
        mocktime = lastblocktime
        for i in range(10):
            mocktime = mocktime + 120
            self.setmocktime(mocktime)
            self.nodes[0].generate(1)
        assert_equal(self.nodes[0].getblockcount(), 111)

        # set the harfork activation to just a few blocks ahead
        bestblock = self.nodes[0].getbestblockhash()
        lastblocktime = self.nodes[0].getblockheader(bestblock)['time']
        activationtime = lastblocktime + 240
        self.setforktime(activationtime)

        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forktime'], activationtime)
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(activationtime, blockchaininfo['mediantime'])

        # Mine just up to the hard fork activation (activationtime will still be greater than mediantime).
        for i in range(6):
            mocktime = mocktime + 120
            self.setmocktime(mocktime)
            self.nodes[0].generate(1)
            blockchaininfo = self.nodes[0].getblockchaininfo()
            assert_equal(blockchaininfo['forkactive'], False)
            assert_equal(blockchaininfo['forkenforcednextblock'], False)
            assert_greater_than(activationtime, blockchaininfo['mediantime']) # activationtime > mediantime
            try:
                tailstorminfo = self.nodes[0].gettailstorminfo()
                assert False; # tailstorm is not enabled yet
            except JSONRPCException as e:
                pass

        # check mininginfo is not enabled for subblocks
        info = self.nodes[0].getmininginfo();
        assert_equal(info["currentmaxblocksize"], 100000);
        assert_equal(info["currentmaxsubblocksize"], "N/A");

        # Fork should be active after the next block mined (median time will be greater than or equal to blocktime)
        mocktime = mocktime + 120
        self.setmocktime(mocktime)
        self.nodes[0].generate(1)
        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], False)
        assert_equal(blockchaininfo['forkenforcednextblock'], True)
        assert_equal(activationtime, blockchaininfo['mediantime']) # when median time is >= activationtime
        self.sync_all()

        # when fork enforced on next block, check mininginfo was enabled for subblocks and also the
        # max blocksize was increased to 100Kb * tailstorm_k = 400Kb
        info = self.nodes[0].getmininginfo();
        assert_equal(info["currentmaxblocksize"], 400000);
        assert_equal(info["currentmaxsubblocksize"], 100000);


        # check node 1 for activation
        blockchaininfo1 = self.nodes[1].getblockchaininfo()
        assert_equal(blockchaininfo1['forkactive'], False)
        assert_equal(blockchaininfo1['forkenforcednextblock'], True)
        assert_equal(activationtime, blockchaininfo1['mediantime']) # when median time is >= activationtime

        # Now we start generating subblocks
        logging.info("Start Generating first subblocks at the fork")
        subblock_hash = self.nodes[0].generate(1)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash[0])
        assert_equal(tailstorminfo['total'], 1)
        assert_equal(tailstorminfo['bestdag'], 1)
        assert_equal(tailstorminfo['competing'], 0) #TODO: not sure this competing is the right value?

        subblock_hash = self.nodes[0].generate(1)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash[0])
        assert_equal(tailstorminfo['total'], 2)
        assert_equal(tailstorminfo['bestdag'], 2)
        assert_equal(tailstorminfo['competing'], 0) #TODO: not sure this competing is the right value?

        subblock_hash = self.nodes[0].generate(1)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash[0])
        assert_equal(tailstorminfo['total'], 3)
        assert_equal(tailstorminfo['bestdag'], 3)
        assert_equal(tailstorminfo['competing'], 0) #TODO: not sure this competing is the right value?

        # Check that block rewards being given out correctly to the right miners
        wallet0 = self.nodes[0].getwalletinfo()
        wallet1 = self.nodes[1].getwalletinfo()
        assert_equal(wallet0['balance'], 180000000)
        assert_equal(wallet0['immature_balance'], 1000000000)
        assert_equal(wallet1['balance'], 0)
        assert_equal(wallet1['immature_balance'], 0)

        # Now we mine the Summary block which locks in the activation
        logging.info("Generate first summary block")
        self.nodes[0].generate(1)
        blockchaininfo = self.nodes[0].getblockchaininfo()
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['total'], 3)
        assert_equal(tailstorminfo['bestdag'], 0)
        assert_equal(tailstorminfo['competing'], 3) #TODO: not sure this competing is the right value?

        info = self.nodes[0].getmininginfo();
        assert_equal(info["currentmaxblocksize"], 400000);
        assert_equal(info["currentmaxsubblocksize"], 100000);

        # Check that block rewards being given out correctly to the right miners
        wallet0 = self.nodes[0].getwalletinfo()
        wallet1 = self.nodes[1].getwalletinfo()
        assert_equal(wallet0['balance'], 190000000)
        assert_equal(wallet0['immature_balance'], 1000000000)
        assert_equal(wallet1['balance'], 0)
        assert_equal(wallet1['immature_balance'], 0)

        # First subblock mined under new rules:
        logging.info("Start Generating first subblocks after new rules")
        self.sync_all()
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        assert_equal(blockchaininfo['forkactive'], True)
        assert_equal(blockchaininfo['forkenforcednextblock'], False)
        assert_greater_than(blockchaininfo['mediantime'], activationtime)
        tailstorminfo = self.nodes[0].gettailstorminfo()
        assert_equal(tailstorminfo['chaintip'], blockchaininfo['bestblockhash'])
        assert_equal(tailstorminfo['dagtip'], subblock_hash[0])
        assert_equal(tailstorminfo['total'], 4)
        assert_equal(tailstorminfo['bestdag'], 1)
        assert_equal(tailstorminfo['competing'], 3) #TODO: not sure this competing is the right value?

        ##### Make sure we don't mine previously mined transactions.
        # Create a transaction that gets added to the txpool in both nodes
        # One subblock is already in the dag.
        # Now mine the remaining subblocks and the summary block. The second
        # subblock should have the transaction in it. The third should not,
        # however, the summary block should have it.
        addr1 = self.nodes[1].getnewaddress()
        txidem = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 1)

        # mine the second subblock. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem in blockdata['txidem'])

        # mine the third subblock. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem not in blockdata['txidem'])

        # mine the Summary block. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        summaryblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getblock(summaryblock_hash[0])
        assert(txidem in blockdata['txidem'])

        # Check that block rewards being given out correctly to the right miners
        self.sync_all()
        waitFor(waitTime, lambda: self.nodes[0].getbalance() == Decimal('199989997.81'))
        waitFor(waitTime, lambda: self.nodes[1].getbalance() == Decimal('10000.00'))
        wallet0 = self.nodes[0].getwalletinfo()
        wallet1 = self.nodes[1].getwalletinfo()
        assert_equal(wallet0['balance'], Decimal('199989997.81'))
        assert_equal(wallet0['unconfirmed_balance'], 0)
        assert_equal(wallet0['immature_balance'], Decimal('1000000002.19'))
        assert_equal(wallet1['balance'], Decimal('10000.00'))
        assert_equal(wallet1['unconfirmed_balance'], Decimal('0.00'))
        assert_equal(wallet1['immature_balance'], 0)

        ##### Make sure we don't mine previously mined transactions when fast block template is enabled.
        # Make sure that fast block template also filters out duplicate transactions
        # that were already mined.
        logging.info("Test fast block template")
        self.nodes[0].set('mining.fastBlockTemplate=1')

        addr1 = self.nodes[1].getnewaddress()
        txidem1 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem2 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem3 = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 3)

        # mine the first subblock. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        # mine the second subblock. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the third subblock but from the other peer. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the Summary block. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        summaryblock_hash = self.nodes[0].generate(1)
        blockdata = self.nodes[0].getblock(summaryblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        ######## Make sure we don't mine previously mined transactions when using a block priority size.
        # Make sure that fast block template also filters out duplicate transactions
        # that were already mined.
        logging.info("Test block priority size")
        self.sync_all()
        self.nodes[0].set('mining.fastBlockTemplate=0')
        self.nodes[0].set('mining.prioritySize=10000')

        addr1 = self.nodes[1].getnewaddress()
        txidem1 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem2 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem3 = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 3)

        # mine the first subblock. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        # mine the second subblock. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the third subblock but from the other peer. The tx should NOT be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        blockdata = self.nodes[0].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # mine the Summary block. The tx should be in it.
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        summaryblock_hash = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        blockdata = self.nodes[0].getblock(summaryblock_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        ######## Startup test where subblocks are shared between nodes
        logging.info("Test sharing of subblocks on startup")
        self.sync_blocks()
        self.nodes[0].set('mining.fastBlockTemplate=0')
        self.nodes[0].set('mining.prioritySize=0')

        # Disconnect peers.
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        # Mine a few subblocks on node 0 and then reconnect
        subblock1 = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        subblock2 = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        subblock3 = self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)

        # Subblocks should now show up on node1 after reconnect.
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        blockdata1 = self.nodes[1].getsubblock(subblock1[0])
        blockdata2 = self.nodes[1].getsubblock(subblock2[0])
        blockdata3 = self.nodes[1].getsubblock(subblock3[0])
        assert(blockdata1['hash'] == subblock1[0])
        assert(blockdata2['hash'] == subblock2[0])
        assert(blockdata3['hash'] == subblock3[0])

        # Now mine the summary block
        summary_block = self.nodes[0].generate(1)
        self.sync_blocks()


        ######## Test with the same transaction in different subblocks
        # This would happen if for instance two miners mined subblocks from their
        # txpools at roughly the same time. This is a key feature of tailstorm that
        # all subblocks are allowed even when they have duplicate transactions.
        # NOTE: this test also tests when we have two subblocks at height 1 or what you could call
        #       two separate tree roots pointing to the same summary block.
        logging.info("Test duplicate transactions in subblocks and two subblocks at height 1")

        # setup both txpools with the same transactions then
        addr1 = self.nodes[1].getnewaddress()
        txidem1 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem2 = self.nodes[0].sendtoaddress(addr1, 10000)
        txidem3 = self.nodes[0].sendtoaddress(addr1, 10000)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 3)

        # Disconnect peers.
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        subblock_hash_node0 = self.nodes[0].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)

        # reconnect peers and both nodes will share subblocks with each other
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)

        blockdata1 = self.nodes[0].getsubblock(subblock_hash_node0[0])
        blockdata2 = self.nodes[0].getsubblock(subblock_hash_node1[0])
        assert(blockdata1['hash'] == subblock_hash_node0[0])
        assert(blockdata2['hash'] == subblock_hash_node1[0])
        assert(txidem1 in blockdata1['txidem'])
        assert(txidem2 in blockdata1['txidem'])
        assert(txidem3 in blockdata1['txidem'])
        assert(txidem1 in blockdata2['txidem'])
        assert(txidem2 in blockdata2['txidem'])
        assert(txidem3 in blockdata2['txidem'])

        blockdata1 = self.nodes[1].getsubblock(subblock_hash_node0[0])
        blockdata2 = self.nodes[1].getsubblock(subblock_hash_node1[0])
        assert(blockdata1['hash'] == subblock_hash_node0[0])
        assert(blockdata2['hash'] == subblock_hash_node1[0])
        assert(txidem1 in blockdata1['txidem'])
        assert(txidem2 in blockdata1['txidem'])
        assert(txidem3 in blockdata1['txidem'])
        assert(txidem1 in blockdata2['txidem'])
        assert(txidem2 in blockdata2['txidem'])
        assert(txidem3 in blockdata2['txidem'])

        # Mine the third subblock which will have no txns in it.
        subblock_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        blockdata = self.nodes[1].getsubblock(subblock_hash[0])
        assert(txidem1 not in blockdata['txidem'])
        assert(txidem2 not in blockdata['txidem'])
        assert(txidem3 not in blockdata['txidem'])

        # Mine the summary block
        wallet0_before = self.nodes[0].getwalletinfo()
        wallet1_before = self.nodes[1].getwalletinfo()
        block_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        blockdata = self.nodes[1].getblock(block_hash[0])
        assert(txidem1 in blockdata['txidem'])
        assert(txidem2 in blockdata['txidem'])
        assert(txidem3 in blockdata['txidem'])

        # check wallet balances
        self.sync_all()
        wallet0_after = self.nodes[0].getwalletinfo()
        wallet1_after = self.nodes[1].getwalletinfo()
        wallet0_balance_delta = wallet0_after['balance'] - wallet0_before['balance']
        wallet0_unconfirmed_balance_delta = wallet0_after['unconfirmed_balance'] - wallet0_before['unconfirmed_balance']
        wallet0_immature_balance_delta = wallet0_after['immature_balance'] - wallet0_before['immature_balance']
        wallet1_balance_delta = wallet1_after['balance'] - wallet1_before['balance']
        wallet1_unconfirmed_balance_delta = wallet1_after['unconfirmed_balance'] - wallet1_before['unconfirmed_balance']
        wallet1_immature_balance_delta = wallet1_after['immature_balance'] - wallet1_before['immature_balance']

        assert_equal(wallet0_balance_delta, Decimal('10000000.00'))
        assert_equal(wallet0_unconfirmed_balance_delta, 0)
        assert_equal(wallet0_immature_balance_delta, Decimal('-8333332.24'))
        assert_equal(wallet1_balance_delta, Decimal('30000.00'))
        assert_equal(wallet1_unconfirmed_balance_delta, Decimal('-30000.00'))
        assert_equal(wallet1_immature_balance_delta, Decimal('8333338.81'))

        ###### Do a few more tests to check correct block reward distribution

        # Test with 2 blocks mined on each peer
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)

        # now mine the summary block
        wallet0_before = self.nodes[0].getwalletinfo()
        wallet1_before = self.nodes[1].getwalletinfo()
        self.nodes[1].generate(1)
        self.sync_all()
        wallet0_after = self.nodes[0].getwalletinfo()
        wallet1_after = self.nodes[1].getwalletinfo()
        wallet0_balance_delta = wallet0_after['balance'] - wallet0_before['balance']
        wallet0_unconfirmed_balance_delta = wallet0_after['unconfirmed_balance'] - wallet0_before['unconfirmed_balance']
        wallet0_immature_balance_delta = wallet0_after['immature_balance'] - wallet0_before['immature_balance']
        wallet1_balance_delta = wallet1_after['balance'] - wallet1_before['balance']
        wallet1_unconfirmed_balance_delta = wallet1_after['unconfirmed_balance'] - wallet1_before['unconfirmed_balance']
        wallet1_immature_balance_delta = wallet1_after['immature_balance'] - wallet1_before['immature_balance']

        assert_equal(wallet0_balance_delta, Decimal('10000000.00'))
        assert_equal(wallet0_unconfirmed_balance_delta, 0)
        assert_equal(wallet0_immature_balance_delta, Decimal('-5000000.00'))
        assert_equal(wallet1_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_unconfirmed_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_immature_balance_delta, Decimal('5000000.00'))

        # Test with 3 blocks mined on one peer and only 1 on the other
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        self.nodes[0].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)

        # now mine the summary block
        wallet0_before = self.nodes[0].getwalletinfo()
        wallet1_before = self.nodes[1].getwalletinfo()
        self.nodes[1].generate(1)
        self.sync_all()
        wallet0_after = self.nodes[0].getwalletinfo()
        wallet1_after = self.nodes[1].getwalletinfo()
        wallet0_balance_delta = wallet0_after['balance'] - wallet0_before['balance']
        wallet0_unconfirmed_balance_delta = wallet0_after['unconfirmed_balance'] - wallet0_before['unconfirmed_balance']
        wallet0_immature_balance_delta = wallet0_after['immature_balance'] - wallet0_before['immature_balance']
        wallet1_balance_delta = wallet1_after['balance'] - wallet1_before['balance']
        wallet1_unconfirmed_balance_delta = wallet1_after['unconfirmed_balance'] - wallet1_before['unconfirmed_balance']
        wallet1_immature_balance_delta = wallet1_after['immature_balance'] - wallet1_before['immature_balance']

        assert_equal(wallet0_balance_delta, Decimal('10000000.00'))
        assert_equal(wallet0_unconfirmed_balance_delta, 0)
        assert_equal(wallet0_immature_balance_delta, Decimal('-2500000.00'))
        assert_equal(wallet1_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_unconfirmed_balance_delta, Decimal('0.00'))
        assert_equal(wallet1_immature_balance_delta, Decimal('2500000.00'))

        # Test re-orgs between dags being built on top of different summary blocks. So in this case
        # there's a summary block race which then we have to decide which dag is our best
        # dag to continue mining on. And if a better dag shows up then we have to follow that
        # and re-org to the other summary block and continue mining on top of that other summary
        # blocks' dag.
        logging.info("Test reorgs between between a summary block race and their two different dags")

        # Mine the next 3 subblocks and share them between peers before disconnecting.
        subblock_hash_node0 = self.nodes[0].generate(3)

        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)

        # Disconnect peers.
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        # Generate a new summary block and then start
        # a new tree by mining a subblock on each peer.
        node0_count = self.nodes[0].getblockcount()
        node1_count = self.nodes[1].getblockcount()
        summary_block_node0 = self.nodes[0].generate(1)
        summary_block_node1 = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].getblockcount() == node0_count + 1)
        waitFor(waitTime, lambda: self.nodes[1].getblockcount() == node1_count + 1)

        # the summary block chain tips on each node should not be equal
        waitFor(waitTime, lambda: self.nodes[0].getbestblockhash() == summary_block_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].getbestblockhash() == summary_block_node1[0])
        node0_chaintip = self.nodes[0].getbestblockhash()
        node1_chaintip = self.nodes[1].getbestblockhash()
        assert_not_equal(node0_chaintip, node1_chaintip)

        # now extend the subblock chain on each peer by one
        subblock_hash_node0 = self.nodes[0].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        assert_not_equal(subblock_hash_node0[0], subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # reconnect peers and both nodes will share subblocks with each other
        # but each peer should stay on it's own previous chain tip.
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) != 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # now mine 1 additional subblock on one of the nodes and this should
        # cause the other node to re-org as evidenced by both having the same
        # chaintip and bestdag hash
        subblock_hash_node1 = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[1].getbestblockhash() == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].getbestblockhash() == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)

        # mine a subblock
        subblock_hash_node1 = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'], node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == node1_chaintip)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # mine the summary block
        summary_hash = self.nodes[1].generate(1)
        waitFor(waitTime, lambda: summary_hash[0] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[0] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        ###### Test where all the subblocks and the summary block should be mined by one miner
        logging.info("Test where all subblocks and summary block are mined by one miner")
        summary_hash = self.nodes[1].generate(4)
        waitFor(waitTime, lambda: summary_hash[3] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[3] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        ###### Test where all the subblocks and the summary block should be mined by one miner
        logging.info("Test multiple blocks to summary block miner")
        self.nodes[1].generate(2)
        summary_hash = self.nodes[1].generate(2)
        waitFor(waitTime, lambda: summary_hash[1] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[1] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        self.nodes[1].generate(1)
        summary_hash = self.nodes[1].generate(3)
        waitFor(waitTime, lambda: summary_hash[2] == self.nodes[1].getbestblockhash())
        waitFor(waitTime, lambda: summary_hash[2] == self.nodes[0].getbestblockhash())
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)

        ###### Test where one node falls behind by more than the subblock check depth
        #      and then catches up again after the check depth has been exceeded.
        logging.info("Test where one node falls behind and then catches up later")
        disconnect_all(self.nodes[0])
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) == 0)

        # make one peer pull ahead before reconnecting
        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        summary_block_node1 = self.nodes[1].generate(1)

        mocktime = mocktime + 30
        self.setmocktime(mocktime)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        subblock_hash_node1 = self.nodes[1].generate(1)
        summary_block_node1 = self.nodes[1].generate(1)

        # connect peers and the nodes should sync
        interconnect_nodes(self.nodes)
        waitFor(waitTime, lambda: len(self.nodes[0].getpeerinfo()) != 0)
        waitFor(waitTime, lambda: self.nodes[1].getbestblockhash() == summary_block_node1[0])
        waitFor(waitTime, lambda: self.nodes[0].getbestblockhash() == summary_block_node1[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 0)
        waitFor(waitTime, lambda: self.nodes[0].getblockcount() == self.nodes[1].getblockcount())


        ###### Test where we create double spent subblocks which forks a subblock tree.
        #      Then test where the double spent fork pull ahead and mines the summary block.
        #      Do the same as above but reorg back to the original tree and then mine a subblock.
        logging.info("Double spend subblocks")

        # mine one subblock so each peer has the same dag of length 1.
        subblock_hash_node0 = self.nodes[0].generate(1);
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 1)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])

        # disconnect peers
        disconnect_all(self.nodes[0])

        # create a two different transactions that spend the same output and send
        # to both peers.
        node1_address = self.nodes[1].getnewaddress("p2pkh", "from0")
        unspent = self.nodes[0].listunspent()

        doublespend_fee = Decimal('-20000')
        doublespend_amt = unspent[0]["amount"] + unspent[1]["amount"] - Decimal("10000000.0")
        rawtx_input_0 = {}
        rawtx_input_0["outpoint"] = unspent[0]["outpoint"]
        rawtx_input_0["amount"] = unspent[0]["amount"]
        rawtx_input_1 = {}
        rawtx_input_1["outpoint"] = unspent[1]["outpoint"]
        rawtx_input_1["amount"] = unspent[1]["amount"]
        inputs = [rawtx_input_0, rawtx_input_1]
        change_address = self.nodes[0].getnewaddress("p2pkt")
        outputs = {}
        outputs[change_address] = Decimal("10000000.0") + doublespend_fee
        outputs[node1_address] = doublespend_amt
        rawtx2 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend2 = self.nodes[0].signrawtransaction(rawtx2)
        assert_equal(doublespend2["complete"], True)

        # Change how we allocate the coins slightly
        outputs[node1_address] =  outputs[node1_address] - Decimal("5000000.0")
        outputs[change_address] = outputs[change_address] + Decimal("5000000.0")
        # And build a doublespend
        rawtx1 = self.nodes[0].createrawtransaction(inputs, outputs)
        doublespend1 = self.nodes[0].signrawtransaction(rawtx1)
        assert_equal(doublespend1["complete"], True)

        # doublespends will have different idems because they change utxo state
        # (as opposed to malleated tx, which have same idem, but different id)
        assert doublespend1["txidem"] != doublespend2["txidem"], "transactions are not different"

        # Now give doublespend1 to one side of the network
        doublespend1_txidem = self.nodes[0].sendrawtransaction(doublespend1["hex"])

        # Now give doublespend2 to other peer
        doublespend2_txidem = self.nodes[1].sendrawtransaction(doublespend2["hex"])

        waitFor(waitTime, lambda: self.nodes[0].gettxpoolinfo()['size'] == 1)
        waitFor(waitTime, lambda: self.nodes[1].gettxpoolinfo()['size'] == 1)

        # mine a subblock on both peers. These subblocks will double spend each other.
        subblock_hash_node0 = self.nodes[0].generate(1);
        subblock_hash_node1 = self.nodes[1].generate(1);
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 11)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 17)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])

        # connect peers. The nodes should share their subblocks and we should
        # end up with a forked a double spend dag on each peer but each peer
        # should be having a different best dag tip but there should be a new
        # double spend tree.
        interconnect_nodes(self.nodes)

        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 2)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 11)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 17)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node1[0])


        # now mine the next subblock on one node causing the other to re-org their dag tree
        # and so both peers should end up on the same dagtip.
        subblock_hash_node0 = self.nodes[0].generate(1);
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['total'] == 13)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['total'] == 19)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['bestdag'] == 3)
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['dagtip'] == subblock_hash_node0[0])

        # Mine the summary block on node 1: both peers should end up on the same node1 chaintip.
        # NOTE: This test also tests that the conflicted txns on node1 got removed from then txpool
        #       on node1 as the previous subblocks were received. If they hadn't been then the summary
        #       could never have been mined because a conflicting tx would have been added
        #       to the summary block before validation.
        summary_hash = self.nodes[1].generate(1);
        waitFor(waitTime, lambda: self.nodes[0].gettailstorminfo()['chaintip'] == summary_hash[0])
        waitFor(waitTime, lambda: self.nodes[1].gettailstorminfo()['chaintip'] == summary_hash[0])


if __name__ == '__main__':
    TailstormActivationTest().main()

def Test():
    t = TailstormActivationTest()
    t.drop_to_pdb = True
    bitcoinConf = {
        "debug": ["validation", "rpc", "net", "blk", "thin", "mempool", "req", "bench", "evict"],
    }
    flags = standardFlags()
    flags[0] = '--tmpdir=/ramdisk/test/t1'
    t.main(flags, bitcoinConf, None)
