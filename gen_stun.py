import os

def create_stun_binding_request():
    # STUN Binding Request: Type 0x0001
    message_type = b'\x00\x01'
    # Message Length: 0x0000 (no additional attributes)
    message_length = b'\x00\x00'
    # Magic Cookie: 0x2112A442
    magic_cookie = b'\x21\x12\xa4\x42'
    # Transaction ID: 12 random bytes
    transaction_id = os.urandom(12)
    
    # Combine all parts to form the message
    stun_message = message_type + message_length + magic_cookie + transaction_id
    return stun_message

# Create the STUN message
stun_message = create_stun_binding_request()

# Write the STUN message to a file
with open('stun_request.bin', 'wb') as f:
    f.write(stun_message)

# Print the STUN message in hexadecimal format for verification
print("STUN Binding Request (hex):", stun_message.hex())

