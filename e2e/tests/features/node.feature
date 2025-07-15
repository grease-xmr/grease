@monero
Feature: Monero node control
  
  Background:
    Given a Monero regtest network

  Scenario: Mine some blocks
    Then the node status is "running"
    When Alice mines 10 blocks
    Then the current block height is 11
    When Alice mines 10 blocks
    Then the current block height is 21
    When I stop the node
    Then the node status is "exited normally"

  Scenario: Shut the node down gracefully
    Then the node status is "running"
    When I stop the node
    Then the node status is "exited normally"

  Scenario: Kill the node
    Then the node status is "running"
    When I kill the node
    Then the node status is "killed"