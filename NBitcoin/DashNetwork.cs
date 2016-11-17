using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NBitcoin.DataEncoders;
using NBitcoin.Protocol;
using NBitcoin.Stealth;
using System.IO;
using System.Threading;

namespace NBitcoin
{
    class DashNetwork
    {
        internal byte[][] base58Prefixes = new byte[14][];

        //Needs IP addresses & ports for dash network
        static string[] pnSeed = new[] {"199.180.128.61:9999","195.2.252.218:9999","191.183.164.52:9999","128.199.125.179:9999","128.199.181.159:9999","185.115.127.168:9999" };


        uint magic;
        byte[] vAlertPubKey;
        PubKey _AlertPubKey;
        public PubKey AlertPubKey
        {
            get
            {
                if (_AlertPubKey == null)
                {
                    _AlertPubKey = new PubKey(vAlertPubKey);
                }
                return _AlertPubKey;
            }
        }

#if !NOSOCKET
        List<DNSSeedData> vSeeds = new List<DNSSeedData>();
        List<NetworkAddress> vFixedSeeds = new List<NetworkAddress>();
#else
		List<string> vSeeds = new List<string>();
		List<string> vFixedSeeds = new List<string>();
#endif
        Block genesis = new Block();

        private int nRPCPort;
        public int RPCPort
        {
            get
            {
                return nRPCPort;
            }
        }

        private int nDefaultPort;
        public int DefaultPort
        {
            get
            {
                return nDefaultPort;
            }
        }


        private readonly Consensus consensus = new Consensus();
        public Consensus Consensus
        {
            get
            {
                return consensus;
            }
        }

        private DashNetwork()
        {
        }

        private int nSubsidyHalvingInterval;
        private string name;

        public string Name
        {
            get
            {
                return name;
            }
        }

        static DashNetwork()
        {
            _Main = new DashNetwork();
            _Main.InitMain();
            _Main.Consensus.Freeze();

            _TestNet = new DashNetwork();
            _TestNet.InitTest();
            _TestNet.Consensus.Freeze();

            _RegTest = new DashNetwork();
            _RegTest.InitReg();
        }

        static DashNetwork _Main;
        public static DashNetwork Main
        {
            get
            {
                return _Main;
            }
        }

        static DashNetwork _TestNet;
        public static DashNetwork TestNet
        {
            get
            {
                return _TestNet;
            }
        }

        static DashNetwork _RegTest;
        public static DashNetwork RegTest
        {
            get
            {
                return _RegTest;
            }
        }


        private void InitMain()
        {
            SpendableCoinbaseDepth = 100;
            name = "Main";

            consensus.SubsidyHalvingInterval = 210000;
            consensus.MajorityEnforceBlockUpgrade = 750;
            consensus.MajorityRejectBlockOutdated = 950;
            consensus.MajorityWindow = 1000;
            consensus.BuriedDeployments[BuriedDeployments.BIP34] = 227931;
            consensus.BuriedDeployments[BuriedDeployments.BIP65] = 388381;
            consensus.BuriedDeployments[BuriedDeployments.BIP66] = 363725;
            consensus.BIP34Hash = new uint256("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
            consensus.PowLimit = new Target(new uint256("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
            consensus.SegWitHeight = 2000000000;
            consensus.PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60); // two weeks
            consensus.PowTargetSpacing = TimeSpan.FromSeconds(10 * 60);
            consensus.PowAllowMinDifficultyBlocks = false;
            consensus.PowNoRetargeting = false;
            consensus.RuleChangeActivationThreshold = 1916; // 95% of 2016
            consensus.MinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

            consensus.BIP9Deployments[BIP9Deployments.TestDummy] = new BIP9DeploymentsParameters(28, 1199145601, 1230767999);
            consensus.BIP9Deployments[BIP9Deployments.CSV] = new BIP9DeploymentsParameters(0, 1462060800, 1493596800);
            consensus.BIP9Deployments[BIP9Deployments.Segwit] = new BIP9DeploymentsParameters(1, 0, 0);

            // The message start string is designed to be unlikely to occur in normal data.
            // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
            // a large 4-byte int at any alignment.
            magic = 0xD9B4BEF9;
            vAlertPubKey = Encoders.Hex.DecodeData("04fc9702847840aaf195de8442ebecedf5b095cdbb9bc716bda9110971b28a49e0ead8564ff0db22209e0374782c093bb899692d524e9d6a6956e7c5ecbcd68284");
            nDefaultPort = 8333;
            nRPCPort = 8332;
            nSubsidyHalvingInterval = 210000;

            genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, Money.Coins(50m));
            consensus.HashGenesisBlock = genesis.GetHash();
            assert(consensus.HashGenesisBlock == uint256.Parse("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
            assert(genesis.Header.HashMerkleRoot == uint256.Parse("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));
#if !NOSOCKET
            vSeeds.Add(new DNSSeedData("bitcoin.sipa.be", "seed.bitcoin.sipa.be")); // Pieter Wuille
            vSeeds.Add(new DNSSeedData("bluematt.me", "dnsseed.bluematt.me")); // Matt Corallo
            vSeeds.Add(new DNSSeedData("dashjr.org", "dnsseed.bitcoin.dashjr.org")); // Luke Dashjr
            vSeeds.Add(new DNSSeedData("bitcoinstats.com", "seed.bitcoinstats.com")); // Christian Decker
            vSeeds.Add(new DNSSeedData("xf2.org", "bitseed.xf2.org")); // Jeff Garzik
            vSeeds.Add(new DNSSeedData("bitcoin.jonasschnelli.ch", "seed.bitcoin.jonasschnelli.ch")); // Jonas Schnelli
#endif
            base58Prefixes[(int)Base58Type.PUBKEY_ADDRESS] = new byte[] { (0) };
            base58Prefixes[(int)Base58Type.SCRIPT_ADDRESS] = new byte[] { (5) };
            base58Prefixes[(int)Base58Type.SECRET_KEY] = new byte[] { (128) };
            base58Prefixes[(int)Base58Type.ENCRYPTED_SECRET_KEY_NO_EC] = new byte[] { 0x01, 0x42 };
            base58Prefixes[(int)Base58Type.ENCRYPTED_SECRET_KEY_EC] = new byte[] { 0x01, 0x43 };
            base58Prefixes[(int)Base58Type.EXT_PUBLIC_KEY] = new byte[] { (0x04), (0x88), (0xB2), (0x1E) };
            base58Prefixes[(int)Base58Type.EXT_SECRET_KEY] = new byte[] { (0x04), (0x88), (0xAD), (0xE4) };
            base58Prefixes[(int)Base58Type.PASSPHRASE_CODE] = new byte[] { 0x2C, 0xE9, 0xB3, 0xE1, 0xFF, 0x39, 0xE2 };
            base58Prefixes[(int)Base58Type.CONFIRMATION_CODE] = new byte[] { 0x64, 0x3B, 0xF6, 0xA8, 0x9A };
            base58Prefixes[(int)Base58Type.STEALTH_ADDRESS] = new byte[] { 0x2a };
            base58Prefixes[(int)Base58Type.ASSET_ID] = new byte[] { 23 };
            base58Prefixes[(int)Base58Type.COLORED_ADDRESS] = new byte[] { 0x13 };
            base58Prefixes[(int)Base58Type.WITNESS_P2WPKH] = new byte[] { 0x6 };
            base58Prefixes[(int)Base58Type.WITNESS_P2WSH] = new byte[] { (10) };

#if !NOSOCKET
            // Convert the pnSeeds array into usable address objects.
            Random rand = new Random();
            TimeSpan nOneWeek = TimeSpan.FromDays(7);
            for (int i = 0; i < pnSeed.Length; i++)
            {
                // It'll only connect to one or two seed nodes because once it connects,
                // it'll get a pile of addresses with newer timestamps.				
                NetworkAddress addr = new NetworkAddress();
                // Seed nodes are given a random 'last seen time' of between one and two
                // weeks ago.
                addr.Time = DateTime.UtcNow - (TimeSpan.FromSeconds(rand.NextDouble() * nOneWeek.TotalSeconds)) - nOneWeek;
                addr.Endpoint = Utils.ParseIpEndpoint(pnSeed[i], DefaultPort);
                vFixedSeeds.Add(addr);
            }
#endif
        }
        private void InitTest()
        {
            name = "TestNet";

            consensus.SubsidyHalvingInterval = 210000;
            consensus.MajorityEnforceBlockUpgrade = 51;
            consensus.MajorityRejectBlockOutdated = 75;
            consensus.MajorityWindow = 100;
            consensus.BuriedDeployments[BuriedDeployments.BIP34] = 21111;
            consensus.BuriedDeployments[BuriedDeployments.BIP65] = 581885;
            consensus.BuriedDeployments[BuriedDeployments.BIP66] = 330776;
            consensus.BIP34Hash = new uint256("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
            consensus.PowLimit = new Target(new uint256("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
            consensus.SegWitHeight = 2000000000;
            consensus.PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60); // two weeks
            consensus.PowTargetSpacing = TimeSpan.FromSeconds(10 * 60);
            consensus.PowAllowMinDifficultyBlocks = true;
            consensus.PowNoRetargeting = false;
            consensus.RuleChangeActivationThreshold = 1512; // 75% for testchains
            consensus.MinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing

            consensus.BIP9Deployments[BIP9Deployments.TestDummy] = new BIP9DeploymentsParameters(28, 1199145601, 1230767999);
            consensus.BIP9Deployments[BIP9Deployments.CSV] = new BIP9DeploymentsParameters(0, 1456790400, 1493596800);
            consensus.BIP9Deployments[BIP9Deployments.Segwit] = new BIP9DeploymentsParameters(1, 1462060800, 1493596800);

            magic = 0x0709110B;

            vAlertPubKey = DataEncoders.Encoders.Hex.DecodeData("04302390343f91cc401d56d68b123028bf52e5fca1939df127f63c6467cdf9c8e2c14b61104cf817d0b780da337893ecc4aaff1309e536162dabbdb45200ca2b0a");
            nDefaultPort = 18333;
            nRPCPort = 18332;
            //strDataDir = "testnet3";

            // Modify the testnet genesis block so the timestamp is valid for a later start.
            genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, Money.Coins(50m));
            consensus.HashGenesisBlock = genesis.GetHash();

            assert(consensus.HashGenesisBlock == uint256.Parse("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));

#if !NOSOCKET
            vFixedSeeds.Clear();
            vSeeds.Clear();
            vSeeds.Add(new DNSSeedData("bitcoin.petertodd.org", "testnet-seed.bitcoin.petertodd.org"));
            vSeeds.Add(new DNSSeedData("bluematt.me", "testnet-seed.bluematt.me"));
            vSeeds.Add(new DNSSeedData("bitcoin.schildbach.de", "testnet-seed.bitcoin.schildbach.de"));
#endif

            base58Prefixes = DashNetwork.Main.base58Prefixes.ToArray();
            base58Prefixes[(int)Base58Type.PUBKEY_ADDRESS] = new byte[] { (111) };
            base58Prefixes[(int)Base58Type.SCRIPT_ADDRESS] = new byte[] { (196) };
            base58Prefixes[(int)Base58Type.SECRET_KEY] = new byte[] { (239) };
            base58Prefixes[(int)Base58Type.EXT_PUBLIC_KEY] = new byte[] { (0x04), (0x35), (0x87), (0xCF) };
            base58Prefixes[(int)Base58Type.EXT_SECRET_KEY] = new byte[] { (0x04), (0x35), (0x83), (0x94) };
            base58Prefixes[(int)Base58Type.STEALTH_ADDRESS] = new byte[] { 0x2b };
            base58Prefixes[(int)Base58Type.ASSET_ID] = new byte[] { 115 };
            base58Prefixes[(int)Base58Type.COLORED_ADDRESS] = new byte[] { 0x13 };
            base58Prefixes[(int)Base58Type.WITNESS_P2WPKH] = new byte[] { (0x03) };
            base58Prefixes[(int)Base58Type.WITNESS_P2WSH] = new byte[] { (40) };
        }
        private void InitReg()
        {
            name = "RegTest";
            consensus.SubsidyHalvingInterval = 150;
            consensus.MajorityEnforceBlockUpgrade = 750;
            consensus.MajorityRejectBlockOutdated = 950;
            consensus.MajorityWindow = 1000;
            consensus.BuriedDeployments[BuriedDeployments.BIP34] = 100000000;
            consensus.BuriedDeployments[BuriedDeployments.BIP65] = 100000000;
            consensus.BuriedDeployments[BuriedDeployments.BIP66] = 100000000;
            consensus.BIP34Hash = new uint256();
            consensus.PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
            consensus.SegWitHeight = 0;
            consensus.PowTargetTimespan = TimeSpan.FromSeconds(14 * 24 * 60 * 60); // two weeks
            consensus.PowTargetSpacing = TimeSpan.FromSeconds(10 * 60);
            consensus.PowAllowMinDifficultyBlocks = true;
            consensus.PowNoRetargeting = true;
            consensus.RuleChangeActivationThreshold = 108;
            consensus.MinerConfirmationWindow = 144;

            magic = 0xDAB5BFFA;
            nSubsidyHalvingInterval = 150;

            consensus.BIP9Deployments[BIP9Deployments.TestDummy] = new BIP9DeploymentsParameters(28, 0, 999999999);
            consensus.BIP9Deployments[BIP9Deployments.CSV] = new BIP9DeploymentsParameters(0, 0, 999999999);
            consensus.BIP9Deployments[BIP9Deployments.Segwit] = new BIP9DeploymentsParameters(1, 0, 999999999);

            genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, Money.Coins(50m));
            consensus.HashGenesisBlock = genesis.GetHash();
            nDefaultPort = 18444;
            nRPCPort = 18332;
            //strDataDir = "regtest";
            assert(consensus.HashGenesisBlock == uint256.Parse("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));

#if !NOSOCKET
            vSeeds.Clear();  // Regtest mode doesn't have any DNS seeds.
#endif
            base58Prefixes = DashNetwork.TestNet.base58Prefixes.ToArray();
            base58Prefixes[(int)Base58Type.PUBKEY_ADDRESS] = new byte[] { (111) };
            base58Prefixes[(int)Base58Type.SCRIPT_ADDRESS] = new byte[] { (196) };
            base58Prefixes[(int)Base58Type.SECRET_KEY] = new byte[] { (239) };
            base58Prefixes[(int)Base58Type.EXT_PUBLIC_KEY] = new byte[] { (0x04), (0x35), (0x87), (0xCF) };
            base58Prefixes[(int)Base58Type.EXT_SECRET_KEY] = new byte[] { (0x04), (0x35), (0x83), (0x94) };
            base58Prefixes[(int)Base58Type.COLORED_ADDRESS] = new byte[] { 0x13 };
        }

        private Block CreateGenesisBlock(uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
        {
            string pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
            Script genesisOutputScript = new Script(Op.GetPushOp(Encoders.Hex.DecodeData("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")), OpcodeType.OP_CHECKSIG);
            return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
        }

        private Block CreateGenesisBlock(string pszTimestamp, Script genesisOutputScript, uint nTime, uint nNonce, uint nBits, int nVersion, Money genesisReward)
        {
            Transaction txNew = new Transaction();
            txNew.Version = 1;
            txNew.AddInput(new TxIn()
            {
                ScriptSig = new Script(Op.GetPushOp(486604799), new Op()
                {
                    Code = (OpcodeType)0x1,
                    PushData = new[] { (byte)4 }
                }, Op.GetPushOp(Encoders.ASCII.DecodeData(pszTimestamp)))
            });
            txNew.AddOutput(new TxOut()
            {
                Value = genesisReward,
                ScriptPubKey = genesisOutputScript
            });
            Block genesis = new Block();
            genesis.Header.BlockTime = Utils.UnixTimeToDateTime(nTime);
            genesis.Header.Bits = nBits;
            genesis.Header.Nonce = nNonce;
            genesis.Header.Version = nVersion;
            genesis.Transactions.Add(txNew);
            genesis.Header.HashPrevBlock = uint256.Zero;
            genesis.UpdateMerkleRoot();
            return genesis;
        }

        private static void assert(bool v)
        {
            if (!v)
                throw new InvalidOperationException("Invalid network");
        }

        public BitcoinSecret CreateBitcoinSecret(string base58)
        {
            return new BitcoinSecret(base58, this);
        }

        /// <summary>
        /// Create a bitcoin address from base58 data, return a BitcoinAddress or BitcoinScriptAddress
        /// </summary>
        /// <param name="base58">base58 address</param>
        /// <exception cref="System.FormatException">Invalid base58 address</exception>
        /// <returns>BitcoinScriptAddress, BitcoinAddress</returns>
        public BitcoinAddress CreateBitcoinAddress(string base58)
        {
            var type = GetBase58Type(base58);
            if (!type.HasValue)
                throw new FormatException("Invalid Base58 version");
            if (type == Base58Type.PUBKEY_ADDRESS)
                return new BitcoinPubKeyAddress(base58, this);
            if (type == Base58Type.SCRIPT_ADDRESS)
                return new BitcoinScriptAddress(base58, this);
            throw new FormatException("Invalid Base58 version");
        }

        public BitcoinScriptAddress CreateBitcoinScriptAddress(string base58)
        {
            return new BitcoinScriptAddress(base58, this);
        }

        private Base58Type? GetBase58Type(string base58)
        {
            var bytes = Encoders.Base58Check.DecodeData(base58);
            for (int i = 0; i < base58Prefixes.Length; i++)
            {
                var prefix = base58Prefixes[i];
                if (prefix == null)
                    continue;
                if (bytes.Length < prefix.Length)
                    continue;
                if (Utils.ArrayEqual(bytes, 0, prefix, 0, prefix.Length))
                    return (Base58Type)i;
            }
            return null;
        }


        public static Network GetNetworkFromBase58Data(string base58, Base58Type? expectedType = null)
        {
            foreach (var network in GetNetworks())
            {
                var type = network.GetBase58Type(base58);
                if (type.HasValue)
                {
                    if (expectedType != null && expectedType.Value != type.Value)
                        continue;
                    if (type.Value == Base58Type.COLORED_ADDRESS)
                    {
                        var raw = Encoders.Base58Check.DecodeData(base58);
                        var version = network.GetVersionBytes(type.Value);
                        raw = raw.Skip(version.Length).ToArray();
                        base58 = Encoders.Base58Check.EncodeData(raw);
                        return GetNetworkFromBase58Data(base58, null);
                    }
                    return network;
                }
            }
            return null;
        }

        /// <summary>
        /// Find automatically the data type and the network to which belong the base58 data
        /// </summary>
        /// <param name="base58">base58 data</param>
        /// <exception cref="System.FormatException">Invalid base58 data</exception>
        public static Base58Data CreateFromBase58Data(string base58, Network expectedNetwork = null)
        {
            if (base58 == null)
                throw new ArgumentNullException("base58");
            bool invalidNetwork = false;
            foreach (var network in GetNetworks())
            {
                var type = network.GetBase58Type(base58);
                if (type.HasValue)
                {
                    if (type.Value == Base58Type.COLORED_ADDRESS)
                    {
                        var inner = BitcoinAddress.Create(BitcoinColoredAddress.GetWrappedBase58(base58, network));
                        if (inner.Network != network)
                            continue;
                    }
                    if (expectedNetwork != null && network != expectedNetwork)
                    {
                        invalidNetwork = true;
                        continue;
                    }
                    return network.CreateBase58Data(type.Value, base58);
                }
            }
            if (invalidNetwork)
                throw new FormatException("Invalid network");
            throw new FormatException("Invalid base58 data");
        }

        public static T CreateFromBase58Data<T>(string base58, Network expectedNetwork = null) where T : Base58Data
        {
            if (base58 == null)
                throw new ArgumentNullException("base58");
            var result = CreateFromBase58Data(base58, expectedNetwork) as T;
            if (result == null)
                throw new FormatException("Invalid base58 data");
            return result;
        }

        public T Parse<T>(string base58) where T : Base58Data
        {
            var type = GetBase58Type(base58);
            if (type.HasValue)
            {
                var result = CreateBase58Data(type.Value, base58) as T;
                if (result == null)
                    throw new FormatException("Invalid base58 data");
                return result;
            }
            throw new FormatException("Invalid base58 data");
        }

        public T TryParse<T>(string base58) where T : Base58Data
        {
            var type = GetBase58Type(base58);
            if (type.HasValue)
            {
                return CreateBase58Data(type.Value, base58) as T;
            }
            return null;
        }

        public Base58Data CreateBase58Data(Base58Type type, string base58)
        {
            //if (type == Base58Type.EXT_PUBLIC_KEY)
            //    return CreateBitcoinExtPubKey(base58);
            //if (type == Base58Type.EXT_SECRET_KEY)
            //    return CreateBitcoinExtKey(base58);
            if (type == Base58Type.PUBKEY_ADDRESS)
                return CreateBitcoinAddress(base58);
            if (type == Base58Type.SCRIPT_ADDRESS)
                return CreateBitcoinScriptAddress(base58);
            if (type == Base58Type.SECRET_KEY)
                return CreateBitcoinSecret(base58);
            //if (type == Base58Type.CONFIRMATION_CODE)
            //    return CreateConfirmationCode(base58);
            //if (type == Base58Type.ENCRYPTED_SECRET_KEY_EC)
            //    return CreateEncryptedKeyEC(base58);
            //if (type == Base58Type.ENCRYPTED_SECRET_KEY_NO_EC)
            //    return CreateEncryptedKeyNoEC(base58);
            //if (type == Base58Type.PASSPHRASE_CODE)
            //    return CreatePassphraseCode(base58);
            //if (type == Base58Type.STEALTH_ADDRESS)
            //    return CreateStealthAddress(base58);
            //if (type == Base58Type.ASSET_ID)
            //    return CreateAssetId(base58);
            //if (type == Base58Type.COLORED_ADDRESS)
            //    return CreateColoredAddress(base58);
            //if (type == Base58Type.WITNESS_P2WPKH)
            //    return CreateWitPubKeyAddress(base58);
            //if (type == Base58Type.WITNESS_P2WSH)
            //    return CreateWitScriptAddress(base58);
            throw new NotSupportedException("Invalid Base58Data type : " + type.ToString());
        }
        //Some of the Below may not be needed:
        //private BitcoinWitScriptAddress CreateWitScriptAddress(string base58)
        //{
        //    return new BitcoinWitScriptAddress(base58, this);
        //}

        //private BitcoinWitPubKeyAddress CreateWitPubKeyAddress(string base58)
        //{
        //    return new BitcoinWitPubKeyAddress(base58, this);
        //}

        //private BitcoinColoredAddress CreateColoredAddress(string base58)
        //{
        //    return new BitcoinColoredAddress(base58, this);
        //}

        //public NBitcoin.OpenAsset.BitcoinAssetId CreateAssetId(string base58)
        //{
        //    return new NBitcoin.OpenAsset.BitcoinAssetId(base58, this);
        //}

        //public BitcoinStealthAddress CreateStealthAddress(string base58)
        //{
        //    return new BitcoinStealthAddress(base58, this);
        //}

        //private BitcoinPassphraseCode CreatePassphraseCode(string base58)
        //{
        //    return new BitcoinPassphraseCode(base58, this);
        //}

        //private BitcoinEncryptedSecretNoEC CreateEncryptedKeyNoEC(string base58)
        //{
        //    return new BitcoinEncryptedSecretNoEC(base58, this);
        //}

        //private BitcoinEncryptedSecretEC CreateEncryptedKeyEC(string base58)
        //{
        //    return new BitcoinEncryptedSecretEC(base58, this);
        //}

        //private Base58Data CreateConfirmationCode(string base58)
        //{
        //    return new BitcoinConfirmationCode(base58, this);
        //}

        //private Base58Data CreateBitcoinExtPubKey(string base58)
        //{
        //    return new BitcoinExtPubKey(base58, this);
        //}


        //public BitcoinExtKey CreateBitcoinExtKey(ExtKey key)
        //{
        //    return new BitcoinExtKey(key, this);
        //}

        //public BitcoinExtPubKey CreateBitcoinExtPubKey(ExtPubKey pubkey)
        //{
        //    return new BitcoinExtPubKey(pubkey, this);
        //}

        //public BitcoinExtKey CreateBitcoinExtKey(string base58)
        //{
        //    return new BitcoinExtKey(base58, this);
        //}

        //public byte[] GetVersionBytes(Base58Type type)
        //{
        //    var prefix = base58Prefixes[(int)type];
        //    if (prefix == null)
        //        throw new InvalidOperationException("The network " + this + " does not have any prefix for base58 " + Enum.GetName(typeof(Base58Type), type));
        //    return prefix.ToArray();
        //}

        public override string ToString()
        {
            return name;
        }

        public Block GetGenesis()
        {
            var block = new Block();
            block.ReadWrite(genesis.ToBytes());
            return block;
        }


        public uint256 GenesisHash
        {
            get
            {
                return consensus.HashGenesisBlock;
            }
        }

        public static IEnumerable<Network> GetNetworks()
        {
            yield return Main;
            yield return TestNet;
            yield return RegTest;
        }

        /// <summary>
        /// Get network from protocol magic number
        /// </summary>
        /// <param name="magic">Magic number</param>
        /// <returns>The network, or null of the magic number does not match any network</returns>
        public static Network GetNetwork(uint magic)
        {
            return GetNetworks().FirstOrDefault(r => r.Magic == magic);
        }

        /// <summary>
        /// Get network from name
        /// </summary>
        /// <param name="name">main,mainnet,testnet,test,testnet3,reg,regtest,seg,segnet</param>
        /// <returns>The network or null of the name does not match any network</returns>
        public static Network GetNetwork(string name)
        {
            if (name == null)
                throw new ArgumentNullException("name");
            name = name.ToLowerInvariant();
            switch (name)
            {
                case "main":
                case "mainnet":
                    return Network.Main;
                case "testnet":
                case "test":
                case "testnet3":
                    return Network.TestNet;
                case "reg":
                case "regtest":
                case "regnet":
                    return Network.RegTest;
                default:
                    return null;
            }
        }

        public BitcoinSecret CreateBitcoinSecret(Key key)
        {
            return new BitcoinSecret(key, this);
        }
        public BitcoinPubKeyAddress CreateBitcoinAddress(KeyId dest)
        {
            if (dest == null)
                throw new ArgumentNullException("dest");
            return new BitcoinPubKeyAddress(dest, this);
        }

        private BitcoinAddress CreateBitcoinScriptAddress(ScriptId scriptId)
        {
            return new BitcoinScriptAddress(scriptId, this);
        }

        public Message ParseMessage(byte[] bytes, ProtocolVersion version = ProtocolVersion.PROTOCOL_VERSION)
        {
            BitcoinStream bstream = new BitcoinStream(bytes);
            Message message = new Message();
            using (bstream.ProtocolVersionScope(version))
            {
                bstream.ReadWrite(ref message);
            }
            if (message.Magic != magic)
                throw new FormatException("Unexpected magic field in the message");
            return message;
        }

#if !NOSOCKET
        public IEnumerable<NetworkAddress> SeedNodes
        {
            get
            {
                return this.vFixedSeeds;
            }
        }
        public IEnumerable<DNSSeedData> DNSSeeds
        {
            get
            {
                return this.vSeeds;
            }
        }
#endif
        public byte[] _MagicBytes;
        public byte[] MagicBytes
        {
            get
            {
                if (_MagicBytes == null)
                {
                    var bytes = new byte[]
                    {
                        (byte)Magic,
                        (byte)(Magic >> 8),
                        (byte)(Magic >> 16),
                        (byte)(Magic >> 24)
                    };
                    _MagicBytes = bytes;
                }
                return _MagicBytes;
            }
        }
        public uint Magic
        {
            get
            {
                return magic;
            }
        }

        public Money GetReward(int nHeight)
        {
            long nSubsidy = new Money(50 * Money.COIN);
            int halvings = nHeight / nSubsidyHalvingInterval;

            // Force block reward to zero when right shift is undefined.
            if (halvings >= 64)
                return Money.Zero;

            // Subsidy is cut in half every 210,000 blocks which will occur approximately every 4 years.
            nSubsidy >>= halvings;

            return new Money(nSubsidy);
        }

        public bool ReadMagic(Stream stream, CancellationToken cancellation, bool throwIfEOF = false)
        {
            byte[] bytes = new byte[1];
            for (int i = 0; i < MagicBytes.Length; i++)
            {
                i = Math.Max(0, i);
                cancellation.ThrowIfCancellationRequested();

                var read = stream.ReadEx(bytes, 0, bytes.Length, cancellation);
                if (read == 0)
                    if (throwIfEOF)
                        throw new EndOfStreamException("No more bytes to read");
                    else
                        return false;
                if (read != 1)
                    i--;
                else if (_MagicBytes[i] != bytes[0])
                    i = _MagicBytes[0] == bytes[0] ? 0 : -1;
            }
            return true;
        }

        public int SpendableCoinbaseDepth
        {
            get;
            private set;
        }
    }
}
