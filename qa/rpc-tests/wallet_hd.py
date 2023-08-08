#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    start_nodes,
    stop_node,
    start_node,
    assert_equal,
    connect_nodes_bi,
    initialize_chain_clean,
)
import logging
import os
import shutil

class WalletHDTest(BitcoinTestFramework):

    def add_options(self, parser):
        parser.add_option("--enableFalcon", dest="enableFalcon", default="0", action="store",
                          help="Choose whether to enable the falcon wallet")

    #def __init__(self):
    #    super().__init__()
        #self.num_nodes = 2
       # self.node_args = [['-usehd=0', '-test.falcon=' + self.options.enableFalcon], ['-usehd=1', '-test.falcon=' + self.options.enableFalcon, '-keypool=0']]

    def setup_chain(self,bitcoinConfDict=None, wallets=None):
        logging.info ("Initializing test directory "+self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 2)

    def setup_network(self):
        self.num_nodes = 2
        self.node_args = [['-usehd=0', '-test.falcon=' + self.options.enableFalcon], ['-usehd=1', '-test.falcon=' + self.options.enableFalcon, '-keypool=0']]

        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, self.node_args)
        self.is_network_split = False
        connect_nodes_bi(self.nodes, 0, 1)

    def run_test (self):
        tmpdir = self.options.tmpdir

        # Make sure we use hd, keep masterkeyid
        masterkeyid = self.nodes[1].getwalletinfo()['hdmasterkeyid']
        assert_equal(len(masterkeyid), 40)

        # Check wallet type
        walletType = "" 
        if (self.options.enableFalcon == "1"):
            walletType = "Falcon"
        else:
            walletType = "Standard"
        assert_equal(self.nodes[1].getwalletinfo()['hdwallettype'], walletType);

        # Import a non-HD private key in the HD wallet
        non_hd_add = self.nodes[0].getnewaddress()
        self.nodes[1].importprivkey(self.nodes[0].dumpprivkey(non_hd_add))

        # This should be enough to keep the master key and the non-HD key 
        self.nodes[1].backupwallet(tmpdir + "hd.bak")
        #self.nodes[1].dumpwallet(tmpdir + "hd.dump")

        # Derive some HD addresses and remember the last
        # Also send funds to each add
        logging.info("Derive HD addresses ...")
        self.nodes[0].generate(101)
        self.sync_blocks()
        hd_add = None
        num_hd_adds = 100
        for i in range(num_hd_adds):
            hd_add = self.nodes[1].getnewaddress()
            hd_info = self.nodes[1].validateaddress(hd_add)
            assert_equal(hd_info["hdkeypath"], "m/0'/0'/"+str(i+1)+"'")
            assert_equal(hd_info["hdmasterkeyid"], masterkeyid)
            self.nodes[0].sendtoaddress(hd_add, 1000000)
            self.nodes[0].generate(1)
        self.nodes[0].sendtoaddress(non_hd_add, 1000000)
        self.nodes[0].generate(1)

        self.sync_blocks()
        assert_equal(self.nodes[1].getbalance(), (num_hd_adds * 1000000) + 1000000)

        logging.info("Restore backup ...")
        stop_node(self.nodes[1], 1)
        os.remove(self.options.tmpdir + "/node1/regtest/wallet.dat")
        shutil.copyfile(tmpdir + "hd.bak", tmpdir + "/node1/regtest/wallet.dat")
        self.nodes[1] = start_node(1, self.options.tmpdir, self.node_args[1])

        # Assert that derivation is deterministic
        logging.info ("Check derivation...")
        hd_add_2 = None
        for _ in range(num_hd_adds):
            hd_add_2 = self.nodes[1].getnewaddress()
            hd_info_2 = self.nodes[1].validateaddress(hd_add_2)
            assert_equal(hd_info_2["hdkeypath"], "m/0'/0'/"+str(_+1)+"'")
            assert_equal(hd_info_2["hdmasterkeyid"], masterkeyid)
        assert_equal(hd_add, hd_add_2)

        # Needs rescan
        logging.info("Rescan ...")
        stop_node(self.nodes[1], 1)
        self.nodes[1] = start_node(1, self.options.tmpdir, self.node_args[1] + ['-rescan'])
        assert_equal(self.nodes[1].getbalance(), (num_hd_adds * 1000000) + 1000000)

        # If the wallet was previously created as a falcon wallet then launch it as a non-falcon wallet and
        # similarly if it was created as a non-falcon wallet then launch it as a falcon wallet.  It should
        # not be possible in either case.
        logging.info("Launch with incorrect HD type ...")
        stop_node(self.nodes[1], 1)
        enableFalcon = "0"
        if (self.options.enableFalcon == "1"):
            enableFalcon = "0"
        else:
            enableFalcon = "1"
        
        try:
            self.nodes[1] = start_node(1, self.options.tmpdir, ['-test.falcon=' + enableFalcon])
            raise AssertionError("Incorrect HD wallet type was launched without error")
        except:
            # PASSED - node should not have started.
            logging.info("   PASSED: Launch failed as expected")


        # cleanup backup file
        os.remove(tmpdir + "hd.bak")


if __name__ == '__main__':
    WalletHDTest().main ()
