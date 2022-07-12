import * as jose from 'https://deno.land/x/jose@v4.8.3/index.ts'

const server = Deno.listen({ port: 8070})
console.log("JWT validation server is running at http://localhost:8070")

const CERT_URL = 'https://cert.provider' //The URL that contains the certificates
const CERT_ISS = 'https://token.provider.example/project'; //The issuer of the JWT token
const CERT_AUD = 'audience'; //The audience of the JWT token
const CERT_ALG = 'RS256'; //The encryption method

let certificates = [];

for await (const request of server){
    const httpRequest = Deno.serveHttp(request);
    for await (const requestEvent of httpRequest){
        const jwttoken = requestEvent.request.headers.get('authorization')?.substring(7);
        if(jwttoken === undefined){
            requestEvent.respondWith(new Response(undefined ,{
                status: 401
            }));
            break
        }
        if(certificates.length === 0){
            const publicKeysRequest = await fetch(CERT_URL);
            certificates = JSON.parse(await publicKeysRequest.text());
        }
        const algorithm = CERT_ALG;
        const keyLikes = await Promise.all(Object.values(certificates).map((key) => {
            if(typeof(key) !== 'string'){console.error("Invalid key type"); return Promise.resolve(null)}
            return  jose.importX509(key, algorithm);
        }))
        console.log(keyLikes);
        const results : jose.JWTVerifyResult[] = [];
        await Promise.all(keyLikes.map(async keyLike => {
            if(keyLike === null){return}
            try{
                const validation = await jose.jwtVerify(jwttoken, keyLike);
                if(
                    validation.payload.exp === undefined || 
                    Math.round(Date.now()/1000) > validation.payload.exp ||
                    validation.payload.iss === undefined ||
                    validation.payload.iss !== CERT_ISS ||
                    validation.payload.aud === undefined ||
                    validation.payload.aud !== CERT_AUD
                    ){return}
                results.push(validation)
            }
            catch{
                return
            }
        }))
        console.log(results);
        let code;
        if(results.length === 0){
            const publicKeysRequest = await fetch(CERT_URL);
            console.log("Failed verification:", jwttoken)
            certificates = JSON.parse(await publicKeysRequest.text());
            code=401
        }else{
            code=200
        }
        requestEvent.respondWith(new Response(undefined ,{
            status: code
        }));
    }
}