self.addEventListener('push', function(event) {
    const data = event.data ? event.data.json() : {};
    const title = data.title || "Reefer Monitor Pro";
    const options = {
        body: data.body || "Nueva alerta del sistema",
        icon: "https://cdn-icons-png.flaticon.com/512/2333/2333203.png", // Icono generico
        badge: "https://cdn-icons-png.flaticon.com/512/2333/2333203.png",
        vibrate: [200, 100, 200, 100, 200]
    };
    event.waitUntil(self.registration.showNotification(title, options));
});