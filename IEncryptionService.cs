namespace EncryptionService;

public interface IEncryptionService
{
	/// <summary>
	///     Returns the object as a encrypted string.
	/// </summary>
	/// <returns>Encoded ciphertext</returns>
	public string Encrypt<T>(T obj);

	/// <summary>
	///     Decrypts the ciphertext and deserializes to T
	/// </summary>
	/// <param name="cipher">Encoded ciphertext</param>
	public T Decrypt<T>(string cipher);
}
