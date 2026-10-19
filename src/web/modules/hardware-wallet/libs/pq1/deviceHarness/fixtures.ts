// Real ERC-7730 calldata cases decoded from the firmware repo's upstream
// registry fixtures (sphincs_rust/tests/erc7730-upstream-fixtures/registry),
// with the texts the firmware renderer is expected to show for each.
// Generated once for the device harness; not used by production code.

export type Erc7730CallFixture = {
  source: string
  description: string
  to: `0x${string}`
  value: bigint
  data: `0x${string}`
  expectedTexts: string[]
}

export const ERC7730_CALL_FIXTURES = {
  wethWrap: {
    source: 'weth/tests/calldata-weth.tests.json',
    description: 'Wrap - chain 1',
    to: '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
    value: 1870000000000000n,
    data: '0xd0e30db076',
    expectedTexts: [
      'Interaction with',
      'WETH',
      'Amount',
      '0.00187 ETH',
      'Max fees',
      '0.00007322104817819 1 ETH'
    ]
  },
  lidoStake: {
    source: 'lido/tests/calldata-stETH.tests.json',
    description: 'Stake ETH - chain 1',
    to: '0xae7ab96520de3a18e5e111b5eaab095312d7fe84',
    value: 1078608424000534547n,
    data: '0xa1903eab0000000000000000000000006dc9657c2d90d57cadffb64239242d06e6103e43',
    expectedTexts: [
      'Interaction with',
      'Lido DAO',
      'Amount to stake',
      '1.0786084240005345 47 ETH',
      'Max fees',
      '0.00000888276061141 8 ETH'
    ]
  },
  wstEthWrap: {
    source: 'lido/tests/calldata-wstETH.tests.json',
    description: 'Wrap stETH - chain 1',
    to: '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0',
    value: 0n,
    data: '0xea598cb00000000000000000000000000000000000000000000000000de0b6b3a763fffe',
    expectedTexts: [
      'Interaction with',
      'Lido DAO',
      'stETH amount',
      '0.99999999999999 9998 stETH',
      'Max fees',
      '0.0000301737051 ETH'
    ]
  },
  aaveSupply: {
    source: 'aave/tests/calldata-lpv3.tests.json',
    description: 'Supply - chain 1',
    to: '0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2',
    value: 0n,
    data: '0x617ba037000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48000000000000000000000000000000000000000000000000000000052c02155600000000000000000000000081ec2081dfb42c5291c55e6123d527eb744a5ffb0000000000000000000000000000000000000000000000000000000000000000',
    expectedTexts: [
      'Interaction with',
      'Aave',
      'Amount to supply',
      '22213.170518 USDC',
      'Collateral recipient',
      '0x81EC2081dfb42C529 1C55e6123D527EB744 a5fFB',
      'Max fees',
      '0.0004653 ETH'
    ]
  },
  uniswapSwap: {
    source: 'uniswap/tests/calldata-UniswapV3Router02.tests.json',
    description: 'Swap - chain 1',
    to: '0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45',
    value: 0n,
    data: '0xb858183f00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000c0fb1c01de1148fa7b1f151a1740e52b375c47f100000000000000000000000000000000000000000000003750313fc45e9e58ac000000000000000000000000000000000000000000000000000334f5fe5f5da1000000000000000000000000000000000000000000000000000000000000002bb5d730d442e1d5b119fb4e5c843c48a64202ef92000bb8c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000000000000000000000',
    expectedTexts: [
      'Interaction with',
      'Uniswap Labs Amount to Send 1020.349393963551 9715 SABAI Minimum to Receive 0.00090265606942 6593 WETH',
      'Max fees',
      '0.00001721819025 ETH'
    ]
  },
  oneInchEthUnoswap: {
    source: '1inch/tests/calldata-AggregationRouterV6.tests.json',
    description: '1inch: AggregationRouterV6: ethUnoswap',
    to: '0x111111125421ca6dc452d289314280a0f8842a65',
    value: 2000000000000000n,
    data: '0xa76dfc3b00000000000000000000000000000000000000000000000000068ea41a18d0d020800000000000000000000004708077eca6bb527a5bbbd6358ffb043a9c1c14d1f115cb',
    expectedTexts: [
      'R',
      'eview transaction to Swap Swipe to review',
      'R',
      'eview transaction to Swap Swipe to review',
      'Interaction with',
      '1inch Network Amount to Send 0.002 ETH Minimum to',
      'R',
      'eceive 1845685323878608 ???',
      'Max fees',
      '0.0000339903385 ETH',
      'R',
      'R'
    ]
  }
} satisfies Record<string, Erc7730CallFixture>
