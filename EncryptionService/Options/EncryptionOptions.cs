using System.ComponentModel.DataAnnotations;

namespace EncryptionService.Options;

public class EncryptionOptions
{
	public const string Encryption = "Encryption";
	[Required] public string Key { get; set; }
}
