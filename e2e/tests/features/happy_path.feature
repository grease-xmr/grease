@grease
Feature: Grease happy path
  
  Background:
    Given a Monero regtest network
    Given Alice runs the grease server
    Given Bob runs the grease server
    # Mine 60 blocks to get enough decoys
    When Alice mines 100 blocks

  Scenario: Grease Happy Path
    When Alice initiates a new channel with Bob
      | customer_balance  |  1.25  |
      | merchant_balance  |  0.00  |
    Then Alice sees the channel status as establishing
    # Let the output become spendable -- FCMP++ will  fix this
    When Alice mines 10 blocks
    When we wait 500 ms
    Then Alice sees the channel status as open