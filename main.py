import json
import base64
import os

def lambda_handler(event, context):
    if not event.get("message"):
      return {
        'statusCode': 400,
        'body': json.dumps({
          "error": "No message provided"
        })
    }
    message = event.get("message")
    key = os.environ["KEY"]
    crypto_key, encrypted_message = encrypt_process(message, key)
    print(f"Crypto key: {crypto_key}")
    return {
        'statusCode': 200,
        "Encrypted message": encrypted_message
    }

def generate_crypto_key(K, len_message) -> list:
  S = [_ for _ in range(256)]
  # value: string to encrypt
  E = [0 for ab in range(len_message)]
  # KSA
  j = 0
  l = len(K)
  for i in range(len(K)):
    j = (j+S[i%l]+ord(K[i]))%256
    S[i], S[j] = S[j], S[i]
  # PRGA
  i, j, k = 0, 0, 0
  while k < len_message:
    i = (i+1) % 256
    j = (j+S[i]) % 256
    S[i], S[j] = S[j], S[i]
    t = (S[i] + S[j]) % 256
    E[k] = S[t]
    k += 1
  return E

def encrypt_process(message, key):
  crypto_key = generate_crypto_key(key, len(message))
  encrypted_message = []
  for k in range(len(message)):
    encrypted_message.append(ord(message[k]) ^ crypto_key[k])
  crypto_key = "".join(str(i) for i in crypto_key)
  encrypted_message = "".join(str(i) for i in encrypted_message)
  return (
      base64.b64encode(crypto_key.encode('ascii')).decode('ascii'), 
      base64.b64encode(encrypted_message.encode('ascii')).decode('ascii')
  )
