import { Injectable } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { createCipheriv, randomBytes, createHash, createDecipheriv } from 'crypto'

@Injectable()
export class EncryptionService {
  private encryptionAlg: string
  private hashingAlg: string

  constructor(private config: ConfigService) {
    this.encryptionAlg = 'aes-256-cbc'
    this.hashingAlg = 'sha256'
  }

  private hashData(data: string, maxLength?: number) {
    const hash = createHash(this.hashingAlg).update(data).digest('hex')

    if (maxLength) {
      return hash.slice(0, maxLength)
    }

    return hash
  }

  encrypt(data: string): string | null {
    if (!data) return null

    // Create the initial vector
    const iv = randomBytes(16).toString('hex')

    // Hash the encryption key and turn it into 32 bytes
    const hashedKey = this.hashData(this.config.get('ENCRYPTION_KEY'), 32)

    // Turn the initial vector to buffer format, it doesn't work in hex format
    const validIv = Buffer.from(iv, 'hex')

    // Create the cipher
    const cipher = createCipheriv(this.encryptionAlg, hashedKey, validIv)

    // Encrypt the data
    const encryptedData = cipher.update(data, 'utf-8', 'hex') + cipher.final('hex')

    // Append the initial vector to the end of the data
    const finalCipher = `${encryptedData}:${iv}`

    return finalCipher
  }

  decrypt(data: string): string | null {
    if (!data) return null

    // Get the initial vector from the data
    const iv = data.split(':')[1]

    // Get the encrypted data
    const encryptedData = data.split(':')[0]

    // Hash the key to a valid length, 32 bytes
    const hashedKey = this.hashData(this.config.get('ENCRYPTION_KEY'), 32)

    // Turn initial vector to buffer format
    const validIv = Buffer.from(iv, 'hex')

    // Create a decipher
    const decipher = createDecipheriv(this.encryptionAlg, hashedKey, validIv)

    // Decrypt the text
    const finalText =
      decipher.update(encryptedData, 'hex', 'utf-8') + decipher.final('utf-8')

    return finalText
  }
}
