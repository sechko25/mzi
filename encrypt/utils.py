def split_in_chunks(list_a, chunk_size):
    for i in range(0, len(list_a), chunk_size):
        yield list_a[i:i + chunk_size]


def shift_left_cycled(b, n):
    cycled_bits = [b[i] for i in range(n)]
    b <<= n
    for i in range(n):
        b.set(cycled_bits[i], len(b) - n + i - 1)

