@grease
Feature: Grease happy path
  
  Background:
    Given a Monero regtest network
    Given Alice runs the grease client
    Given Bob runs the grease client
    # Mine 60 blocks to get enough decoys
    When Alice mines 60 blocks

  Scenario: Grease Happy Path
    When Alice initiates a new channel with Bob
      | customer_balance  |  1.25  |
      | merchant_balance  |  0.00  |
