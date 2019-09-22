def add(response):
    response.headers.set('Strict-Transport-Security','max-age=3600; includeSubDomains')
    response.headers.set('X-Frame-Options','DENY')
    response.headers.set('X-Content-Type-Options','nosniff')
    response.headers.set('Referer-Policy','same-origin')
    response.headers.set('Feature-Policy',"geolocation 'self'; microphone 'self'; camera 'self';")
    return response