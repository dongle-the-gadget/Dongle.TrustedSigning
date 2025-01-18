using Azure.Core;

namespace Dongle.TrustedSigning;

public class UserSuppliedCredential(string userToken, DateTimeOffset expirationOffset) : TokenCredential
{
    public string UserToken { get; set; } = userToken;

    public DateTimeOffset ExpirationOffset { get; set; } = expirationOffset;

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new AccessToken(UserToken, ExpirationOffset);
    }

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new ValueTask<AccessToken>(new AccessToken(UserToken, ExpirationOffset));
    }
}
