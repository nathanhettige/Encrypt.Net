using EncryptionService.Options;
using EncryptionService.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace EncryptionService.Tests;

public class EncryptionServiceTests
{
	private readonly EncryptionOptions _encryptionOptions = new()
	{
		Key = "x!A%D*G-KaPdSgVkYp2s5v8y/B?E(H+M"
	};

	[Fact]
	public void AesEncryptionServiceTest()
	{
		// Arrange
		var encryptionService = new AesEncryptionService(new OptionsWrapper<EncryptionOptions>(_encryptionOptions), NullLogger<AesEncryptionService>.Instance);
		var obj = new Object("Field", new Dictionary<string, string>
		{
			{ "Question", "Answer" }
		});

		// Act
		var encryptedData = encryptionService.Encrypt(obj);
		var decryptedData = encryptionService.Decrypt<Object>(encryptedData);

		// Assert
		Assert.False(string.IsNullOrWhiteSpace(encryptedData));
		Assert.Equal(obj.Field, decryptedData.Field);
		Assert.Equal(obj.Dictionary, decryptedData.Dictionary);
	}
}

public class Object
{
	public Object(string field, Dictionary<string, string> dictionary)
	{
		Field = field;
		Dictionary = dictionary;
	}
	public string Field { get; init; }
	public Dictionary<string, string> Dictionary { get; init; }
}
