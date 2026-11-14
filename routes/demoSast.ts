
import https from 'https'

export function appelNonVerifie (url: string) {
  // vérification du certificat TLS désactivée : vulnérabilité
  return https.get(url, { rejectUnauthorized: false })
}
