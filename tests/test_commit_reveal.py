import time

from bittensor_drand import get_encrypted_commit

SUBTENSOR_PULSE_DELAY = 24
PERIOD = 3  # Drand period in seconds
GENESIS_TIME = 1692803367


def test_get_encrypted_commits():
    uids = [1, 2]
    weights = [11, 22]
    version_key = 50
    tempo = 100
    current_block = 1000
    netuid = 1
    reveal_period = 2
    block_time = 12
    hotkey = bytes([1, 2, 3])

    start_time = int(time.time())
    ct_pybytes, reveal_round = get_encrypted_commit(
        uids,
        weights,
        version_key,
        tempo,
        current_block,
        netuid,
        reveal_period,
        block_time,
        hotkey,
    )

    # Basic checks
    assert ct_pybytes is not None and len(ct_pybytes) > 0, (
        "Ciphertext should not be empty"
    )
    assert reveal_round > 0, "Reveal round should be positive"

    expected_reveal_round, _, _ = compute_expected_reveal_round(
        start_time, tempo, current_block, netuid, reveal_period, block_time
    )

    # The reveal_round should be close to what we predict
    assert abs(reveal_round - expected_reveal_round) <= 1, (
        f"Reveal round {reveal_round} not close to expected {expected_reveal_round}"
    )


def test_generate_commit_success():
    uids = [1, 2, 3]
    values = [10, 20, 30]
    version_key = 42
    tempo = 50
    current_block = 500
    netuid = 100
    subnet_reveal_period_epochs = 2
    block_time = 12
    hotkey = bytes([1, 2, 3])

    start_time = int(time.time())
    ct_pybytes, reveal_round = get_encrypted_commit(
        uids,
        values,
        version_key,
        tempo,
        current_block,
        netuid,
        subnet_reveal_period_epochs,
        block_time,
        hotkey,
    )

    assert ct_pybytes is not None and len(ct_pybytes) > 0, (
        "Ciphertext should not be empty"
    )
    assert reveal_round > 0, "Reveal round should be positive"

    expected_reveal_round, expected_reveal_time, time_until_reveal = (
        compute_expected_reveal_round(
            start_time,
            tempo,
            current_block,
            netuid,
            subnet_reveal_period_epochs,
            block_time,
        )
    )

    assert abs(reveal_round - expected_reveal_round) <= 1, (
        f"Reveal round {reveal_round} differs from expected {expected_reveal_round}"
    )

    required_lead_time = SUBTENSOR_PULSE_DELAY * PERIOD
    computed_reveal_time = (
        GENESIS_TIME + (reveal_round + SUBTENSOR_PULSE_DELAY) * PERIOD
    )
    assert computed_reveal_time - start_time >= required_lead_time, (
        "Not enough lead time before reveal. "
        f"computed_reveal_time={computed_reveal_time}, start_time={start_time}, required={required_lead_time}"
    )

    assert time_until_reveal >= SUBTENSOR_PULSE_DELAY * PERIOD, (
        f"time_until_reveal {time_until_reveal} is less than required {SUBTENSOR_PULSE_DELAY * PERIOD}"
    )


def test_generate_commit_various_tempos():
    NETUID = 1
    CURRENT_BLOCK = 100_000
    SUBNET_REVEAL_PERIOD_EPOCHS = 1
    BLOCK_TIME = 12
    TEMPOS = [10, 50, 100, 250, 360, 500, 750, 1000]

    uids = [0]
    values = [100]
    version_key = 1
    hotkey = bytes([1, 2, 3])

    for tempo in TEMPOS:
        start_time = int(time.time())

        ct_pybytes, reveal_round = get_encrypted_commit(
            uids,
            values,
            version_key,
            tempo,
            CURRENT_BLOCK,
            NETUID,
            SUBNET_REVEAL_PERIOD_EPOCHS,
            BLOCK_TIME,
            hotkey,
        )

        assert len(ct_pybytes) > 0, f"Ciphertext is empty for tempo {tempo}"
        assert reveal_round > 0, f"Reveal round is zero or negative for tempo {tempo}"

        expected_reveal_round, _, time_until_reveal = compute_expected_reveal_round(
            start_time,
            tempo,
            CURRENT_BLOCK,
            NETUID,
            SUBNET_REVEAL_PERIOD_EPOCHS,
            BLOCK_TIME,
        )

        assert abs(reveal_round - expected_reveal_round) <= 1, (
            f"Tempo {tempo}: reveal_round {reveal_round} not close to expected {expected_reveal_round}"
        )

    computed_reveal_time = (
        GENESIS_TIME + (reveal_round + SUBTENSOR_PULSE_DELAY) * PERIOD
    )
    required_lead_time = SUBTENSOR_PULSE_DELAY * PERIOD

    if time_until_reveal >= required_lead_time:
        assert computed_reveal_time - start_time >= required_lead_time, (
            f"Not enough lead time: reveal_time={computed_reveal_time}, "
            f"start_time={start_time}, required={required_lead_time}"
        )


def compute_expected_reveal_round(
    now: int,
    tempo: int,
    current_block: int,
    netuid: int,
    subnet_reveal_period_epochs: int,
    block_time: int,
):
    tempo_plus_one = tempo + 1
    netuid_plus_one = netuid + 1
    block_with_offset = current_block + netuid_plus_one
    current_epoch = block_with_offset // tempo_plus_one

    reveal_epoch = current_epoch + subnet_reveal_period_epochs
    first_reveal_blk = reveal_epoch * tempo_plus_one - netuid_plus_one

    # Rust adds SECURITY_BLOCK_OFFSET = 3
    SECURITY_BLOCK_OFFSET = 3
    target_ingest_blk = first_reveal_blk + SECURITY_BLOCK_OFFSET

    blocks_until_ingest = max(target_ingest_blk - current_block, 0)
    secs_until_ingest = blocks_until_ingest * block_time

    target_secs = now + secs_until_ingest

    # Rust uses floor() and does NOT subtract SUBTENSOR_PULSE_DELAY
    reveal_round = int((target_secs - GENESIS_TIME) / PERIOD)

    if reveal_round < 1:
        reveal_round = 1

    reveal_time = target_secs
    time_until_reveal = secs_until_ingest

    return reveal_round, reveal_time, time_until_reveal
