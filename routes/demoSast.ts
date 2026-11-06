import https from 'node:https'

// Démo quality gate : failles volontaires
export function fetchPartnerData (url: string) {
  // Vulnérabilité : vérification du certificat TLS désactivée (MITM possible)
  return https.get(url, { rejectUnauthorized: false })
}

export function runUserScript (code: string) {
  // Security hotspot : exécution dynamique de code
  return eval(code)
}
