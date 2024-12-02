const getRefreshToken = async () => {

    // refresh token that has been previously stored
    const refreshToken = localStorage.getItem('refresh_token');
    const url = "https://accounts.spotify.com/api/token";

    const payload = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: clientId
        }),
    }
    const body = await fetch(url, payload);
    const response = await body.json();

    localStorage.setItem('access_token', response.accessToken);
    if (response.refreshToken) {
        localStorage.setItem('refresh_token', response.refreshToken);
    }
}

const generateRandomString = (length) => {
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const values = crypto.getRandomValues(new Uint8Array(length));
    return values.reduce((acc, x) => acc + possible[x % possible.length], "");
}

const sha256 = async (plain) => {
    const encoder = new TextEncoder()
    const data = encoder.encode(plain)
    return window.crypto.subtle.digest('SHA-256', data)
}
const base64encode = (input) => {
    return btoa(String.fromCharCode(...new Uint8Array(input)))
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
}

function user_authorization() {
    const clientId = '61e27c75288442e492a4585b195b1750';
    const redirectUri = 'https://github.com/rryyii/rryyii.github.io';

    const scope = 'user-read-private user-read-email';
    const authUrl = new URL("https://accounts.spotify.com/authorize")

    // generated in the previous step
    window.localStorage.setItem('code_verifier', codeVerifier);

    const params = {
        response_type: 'code',
        client_id: clientId,
        scope,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge,
        redirect_uri: redirectUri,
    }

    authUrl.search = new URLSearchParams(params).toString();
    window.location.href = authUrl.toString();

}

async function token() {
    const codeVerifier = generateRandomString(64);
    const hashed = await sha256(codeVerifier)
    const codeChallenge = base64encode(hashed);
    user_authorization();
    const urlParams = new URLSearchParams(window.location.search);
    const authCode = urlParams.get('code');
    // codeVerifier MUST be the same as the one used to make the code challenge for the auth request
    const codeVerifier2 = localStorage.getItem('code_verifier');

    const payload = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: '61e27c75288442e492a4585b195b1750',
            redirect_uri: 'https://github.com/rryyii/rryyii.github.io',
            code_verifier: codeVerifier2,
            code: authCode, // From the URL
        }),
    }

    const response = await fetch('https://accounts.spotify.com/api/token', payload);
    const data = await response.json();

    const accessToken = data.access_token;
    alert(accessToken);
}

token();

