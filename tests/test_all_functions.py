import time
import bittensor_drand as btcr


def test_get_latest_round():
    round_ = btcr.get_latest_round()
    assert isinstance(round_, int)
    assert round_ > 0


def test_encrypt_and_decrypt():
    data = b"hello, bittensor!"
    n_blocks = 1

    encrypted, reveal_round = btcr.encrypt(data, n_blocks)
    assert isinstance(encrypted, bytes)
    assert isinstance(reveal_round, int)

    print(f"Reveal round: {reveal_round}")
    current_round = btcr.get_latest_round()

    if current_round < reveal_round:
        print("Waiting for reveal round to arrive...")
        while btcr.get_latest_round() < reveal_round:
            time.sleep(3)

    decrypted = btcr.decrypt(encrypted)
    assert decrypted is not None
    assert decrypted == data

def test_encrypt_at_round_and_decrypt():
    data = b"test data for specific round"
    
    # Get a round that's already revealed (in the past)
    current_round = btcr.get_latest_round()
    past_round = current_round - 100  # Use a round from the past
    
    # Encrypt at specific round
    encrypted, returned_round = btcr.encrypt_at_round(data, past_round)
    assert isinstance(encrypted, bytes)
    assert returned_round == past_round
    
    # Should be able to decrypt immediately since the round is in the past
    decrypted = btcr.decrypt(encrypted)
    assert decrypted is not None
    assert decrypted == data
    
    # Test with future round
    future_round = current_round + 1000
    encrypted_future, returned_future_round = btcr.encrypt_at_round(data, future_round)
    assert isinstance(encrypted_future, bytes)
    assert returned_future_round == future_round
    
    # Attempting to decrypt future round should fail or return None
    decrypted_future = btcr.decrypt(encrypted_future, no_errors=True)
    assert decrypted_future is None  # Can't decrypt yet
    
def test_get_encrypted_commitment():
    encrypted, round_ = btcr.get_encrypted_commitment("my_commitment", 1)
    assert isinstance(encrypted, bytes)
    assert isinstance(round_, int)


def test_get_encrypted_commit():
    uids = [0, 1]
    weights = [100, 200]
    version_key = 1
    tempo = 10
    current_block = 100
    netuid = 1
    subnet_reveal_period_epochs = 2
    block_time = 12.0
    hotkey = b"test_hotkey_bytes_32_characters!"

    encrypted, round_ = btcr.get_encrypted_commit(
        uids,
        weights,
        version_key,
        tempo,
        current_block,
        netuid,
        subnet_reveal_period_epochs,
        block_time,
        hotkey,
    )
    assert isinstance(encrypted, bytes)
    assert isinstance(round_, int)


def test_get_signature_for_round():
    # Get a past round that's already revealed
    current_round = btcr.get_latest_round()
    past_round = current_round - 100

    # Fetch signature for that round
    signature = btcr.get_signature_for_round(past_round)
    assert isinstance(signature, str)
    assert len(signature) > 0
    # Drand signatures are hex-encoded, so should only contain hex characters
    assert all(c in '0123456789abcdef' for c in signature.lower())


def test_decrypt_with_signature():
    # Test basic decrypt_with_signature functionality
    data = b"test data for signature decryption"

    # Get a round that's already revealed
    current_round = btcr.get_latest_round()
    past_round = current_round - 100

    # Encrypt at that round
    encrypted, returned_round = btcr.encrypt_at_round(data, past_round)
    assert returned_round == past_round

    # Fetch signature separately
    signature = btcr.get_signature_for_round(past_round)

    # Decrypt using the signature
    decrypted = btcr.decrypt_with_signature(encrypted, signature)
    assert decrypted == data


def test_batch_decryption_optimization():
    """Test the main use case: decrypting multiple ciphertexts with one signature fetch."""
    # Simulate batch encryption for the same round
    messages = [
        b"message 1",
        b"message 2",
        b"message 3",
        b"message 4",
        b"message 5",
    ]

    # Get a past round
    current_round = btcr.get_latest_round()
    past_round = current_round - 100

    # Encrypt all messages at the same round
    encrypted_messages = [
        btcr.encrypt_at_round(msg, past_round)[0] for msg in messages
    ]

    # Fetch signature once
    signature = btcr.get_signature_for_round(past_round)

    # Decrypt all messages using the same signature (no additional API calls)
    decrypted_messages = [
        btcr.decrypt_with_signature(enc, signature) for enc in encrypted_messages
    ]

    # Verify all messages decrypted correctly
    assert decrypted_messages == messages
    print(f"Successfully decrypted {len(messages)} messages with a single signature fetch!")
