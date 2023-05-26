using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EncryptionService.Options;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EncryptionService.Services;

/// <summary>
///     Implements AES using a 256-bit key.
/// </summary>
/// <see cref="https://learn.microsoft.com/en-us/dotnet/standard/security/encrypting-data" />
public class AesEncryptionService : IEncryptionService
{
	private readonly byte[] _key;
	private readonly ILogger _logger;

	public AesEncryptionService(IOptions<EncryptionOptions> options, ILogger<AesEncryptionService> logger)
	{
		_logger = logger;
		_key = Encoding.UTF8.GetBytes(options.Value.Key);
	}

	/// <summary>
	///     Encryption steps:
	///     1. JSON serialize object
	///     2. Generate random IV and write into a memory stream
	///     3. Encrypt JSON with _key and IV and write into memory stream
	///     4. Write memory stream to byte[] and return as base64 encoded string
	/// </summary>
	/// <returns>Base64 encoded string</returns>
	public string Encrypt<T>(T obj)
	{
		try
		{
			var json = JsonSerializer.Serialize(obj);

			using (var memoryStream = new MemoryStream())
			{
				using (var aes = Aes.Create())
				{
					aes.Key = _key;
					var iv = aes.IV;
					memoryStream.Write(iv, 0, iv.Length);

					using (CryptoStream cryptoStream = new(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
					{
						using (StreamWriter encryptWriter = new(cryptoStream))
						{
							encryptWriter.WriteLine(json);
						}
					}
				}

				var ciphertext = Convert.ToBase64String(memoryStream.ToArray());
				return ciphertext;
			}
		}
		catch (Exception e)
		{
			_logger.LogError("Encryption failed");
			throw;
		}
	}

	/// <summary>
	///     Decrypt steps:
	///     1. Convert base64 encoded cipher to byte stream
	///     2. Read IV from first 16 bytes
	///     3. Use IV and _key to decrypt the rest of the byte stream containing the JSON
	///     4. Return deserialized JSON
	/// </summary>
	/// <returns>T</returns>
	public T Decrypt<T>(string cipher)
	{
		var encryptedData = Convert.FromBase64String(cipher);

		try
		{
			using (var memoryStream = new MemoryStream(encryptedData))
			{
				using (var aes = Aes.Create())
				{
					var key = _key;
					var iv = new byte[aes.IV.Length];
					var numBytesToRead = aes.IV.Length;
					var numBytesRead = 0;
					while (numBytesToRead > 0)
					{
						var n = memoryStream.Read(iv, numBytesRead, numBytesToRead);
						if (n == 0) break;

						numBytesRead += n;
						numBytesToRead -= n;
					}

					using (CryptoStream cryptoStream = new(
						       memoryStream,
						       aes.CreateDecryptor(key, iv),
						       CryptoStreamMode.Read))
					{
						using (StreamReader decryptReader = new(cryptoStream))
						{
							var decryptedMessage = decryptReader.ReadToEnd();
							return JsonSerializer.Deserialize<T>(decryptedMessage)!;
						}
					}
				}
			}
		}
		catch (Exception e)
		{
			_logger.LogError("Decryption failed");
			throw;
		}
	}
}
