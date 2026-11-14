import https from 'https'

export function appelNonVerifie (url: string) {
  // vérification du certificat TLS désactivée
  return https.get(url, { rejectUnauthorized: false })
}

export function executer (code: string) {
  // exécution dynamique de code : injection possible
  return eval(code)
}
