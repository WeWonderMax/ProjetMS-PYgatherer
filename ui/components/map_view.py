"""
Map View Component
"""

from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import QUrl

class MapView(QWebEngineView):
    """Interactive map view component"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.is_map_ready = False
        self.pending_update = None
        self.setup_initial_map()

    def setup_initial_map(self):
        """Setup initial empty map centered on world view"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>IP Location Map</title>
            <meta charset="utf-8" />
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
            <script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>
            <style>
                #map {
                    height: 100vh;
                    width: 100%;
                }
                body {
                    margin: 0;
                    padding: 0;
                }
                .custom-popup {
                    font-size: 14px;
                    line-height: 1.5;
                }
            </style>
        </head>
        <body>
            <div id="map"></div>
            <script>
                var map;
                var marker;
                var circle;
                
                function initMap() {
                    map = L.map('map').setView([0, 0], 2);
                    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                        maxZoom: 19,
                        attribution: '© OpenStreetMap contributors'
                    }).addTo(map);
                    window.mapInitialized = true;
                }

                function updateLocation(lat, lon, details) {
                    if (!window.mapInitialized) {
                        initMap();
                    }

                    // Remove previous markers and circles
                    if (marker) {
                        map.removeLayer(marker);
                    }
                    if (circle) {
                        map.removeLayer(circle);
                    }

                    // Center and zoom the map
                    map.setView([lat, lon], 10);

                    // Add marker with custom icon
                    marker = L.marker([lat, lon], {
                        icon: L.icon({
                            iconUrl: 'https://raw.githubusercontent.com/pointhi/leaflet-color-markers/master/img/marker-icon-2x-red.png',
                            iconSize: [25, 41],
                            iconAnchor: [12, 41],
                            popupAnchor: [1, -34]
                        })
                    }).addTo(map);

                    // Add circle to highlight the area
                    circle = L.circle([lat, lon], {
                        color: 'red',
                        fillColor: '#f03',
                        fillOpacity: 0.2,
                        radius: 5000
                    }).addTo(map);

                    // Create popup content
                    var popupContent = '<div class="custom-popup">' +
                        '<h3>Location Details</h3>' +
                        '<p>' + details + '</p>' +
                        '<p><strong>Coordinates:</strong> ' + lat + ', ' + lon + '</p>' +
                        '</div>';

                    // Bind popup to marker
                    marker.bindPopup(popupContent).openPopup();

                    // Fit bounds to show both marker and circle
                    map.fitBounds(circle.getBounds());
                }

                // Initialize map when page loads
                document.addEventListener('DOMContentLoaded', initMap);
            </script>
        </body>
        </html>
        """
        self.setHtml(html_content, QUrl("https://unpkg.com/"))
        self.loadFinished.connect(self._on_load_finished)

    def _on_load_finished(self, ok):
        """Called when the web page has finished loading"""
        if ok:
            self.is_map_ready = True
            if self.pending_update:
                self.update_location(*self.pending_update)
                self.pending_update = None

    def update_location(self, latitude, longitude, details):
        """Update map with new location"""
        try:
            if not self.is_map_ready:
                self.pending_update = (latitude, longitude, details)
                return

            # JavaScript to update map
            js_code = f"updateLocation({latitude}, {longitude}, '{details}')"
            self.page().runJavaScript(js_code)
            return True
            
        except Exception as e:
            print(f"Error updating map location: {str(e)}")
            return False
