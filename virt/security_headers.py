def add(response):
    response.headers.set('Strict-Transport-Security','max-age=2592000; includeSubDomains')
    response.headers.set('X-Frame-Options','DENY')
    response.headers.set('X-Content-Type-Options','nosniff')
    response.headers.set('Referrer-Policy','same-origin')
    response.headers.set('Feature-Policy',"geolocation 'self'; microphone 'self'; camera 'self';")
    response.headers.set('Content-Security-Policy',"default-src 'self'; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; style-src 'self' https://fonts.googleapis.com;")
    return response