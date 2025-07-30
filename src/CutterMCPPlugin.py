import cutter
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel,
    QPlainTextEdit, QPushButton
)
from PySide6.QtCore import Qt, QObject, Signal
from urllib.parse import urlparse, parse_qs

class ServerSignals(QObject):
    log_signal = Signal(str)
    status_signal = Signal(str)

class MCPDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent, signals):
        super().__init__(parent)
        self.setObjectName("MCPDockWidget")
        self.setWindowTitle("HTTP Server")
        self.signals = signals

        container = QWidget()
        layout = QVBoxLayout(container)

        self.status_label = QLabel("🟢 HTTP Server: Running (Port 8000)")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("HTTP Server logs will appear here...")
        layout.addWidget(self.log_view)

        self.setWidget(container)

        self.signals.log_signal.connect(self.log)

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{timestamp}] {message}")

class MCPPlugin(cutter.CutterPlugin):
    def __init__(self):
        super().__init__()
        self.server = None
        self.server_thread = None
        self.signals = ServerSignals()
        self.dock_widget = None

    class MCPRequestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            message = format % args
            self.server.parent.signals.log_signal.emit(message)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)

            if path == '/functions':
                self.handle_functions(query)
            elif path == '/decompile':
                self.handle_decompile(query)
            elif path == '/segments':
                self.handle_segments(query)
            elif path == '/imports':
                self.handle_imports(query)
            elif path == '/exports':
                self.handle_exports(query)
            elif path == '/data':
                self.handle_data(query)
            elif path == '/searchFunctions':
                self.handle_search_functions(query)
            elif path == '/libraries':
                self.handle_libraries(query)
            elif path == '/headers':
                self.handle_headers(query)
            elif path == '/showFunctionDetails':
                self.handle_show_function_details(query)
            elif path == '/getFunctionPrototype':
                self.handle_get_function_prototype(query)
            elif path == '/xrefsTo':
                self.handle_xrefs_to(query)
            elif path == '/disassembleFunction':
                self.handle_disassemble_function(query)
            else:
                self.handle_root()

        def do_POST(self):
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            parsed = urlparse(self.path)
            if parsed.path == '/renameFunction':
                self.handle_rename_function(post_data)
            elif parsed.path == '/setDecompilerComment':
                self.handle_set_decompiler_comment(post_data)
            elif parsed.path == '/setFunctionPrototype':
                self.handle_set_function_prototype(post_data)
            else:
                self.send_error(404, "Endpoint not found")

        def handle_root(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            response = """HTTP Server Endpoints:
GET /functions - List all functions
GET /decompile?addr=ADDR - Decompile function
GET /segments - List memory segments
GET /imports - List imports
GET /exports - List exports
GET /data - List defined data
GET /searchFunctions?query=NAME - Search functions
GET /libraries - List shared libraries
GET /headers - Show header information
GET /showFunctionDetails?addr=ADDR - Show details about function
GET /getFunctionPrototype?addr=ADDR - Get function signature
GET /xrefsTo?addr=ADDR - List code references
GET /disassembleFunction?addr=ADDR - Disassemble function

POST /renameFunction - Rename a function
POST /setDecompilerComment - Set decompiler comment
POST /setFunctionPrototype - Set function signature"""
            self.wfile.write(response.encode('utf-8'))

        def handle_rename_function(self, post_data):
            try:
                params = parse_qs(post_data.decode('utf-8'))
                function_address = params.get('address', [''])[0]
                new_name = params.get('newName', [''])[0]

                if not function_address or not new_name:
                    self.send_error(400, "Both address and newName parameters are required")
                    return

                cutter.cmd(f"afn {new_name} @ {function_address}")
                self.server.parent.signals.log_signal.emit(f"Renamed function at {function_address} to {new_name}")

                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Successfully renamed function at {function_address} to {new_name}".encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error renaming function: {str(e)}")

        def handle_set_decompiler_comment(self, post_data):
            try:
                params = parse_qs(post_data.decode('utf-8'))
                address = params.get('address', [''])[0]
                comment = params.get('comment', [''])[0]

                if not address or not comment:
                    self.send_error(400, "Both address and comment parameters are required")
                    return

                cutter.cmd(f"CCu {comment} @ {address}")
                self.server.parent.signals.log_signal.emit(f"Set decompiler comment at {address} to: {comment}")

                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Successfully set decompiler comment at {address}".encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error setting decompiler comment: {str(e)}")

        def handle_functions(self, query):
            try:
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                funcs = cutter.cmd("aflq").splitlines()
                paginated_funcs = funcs[offset:offset+limit]
                response = "\n".join(paginated_funcs)
                self.server.parent.signals.log_signal.emit(f"Served {len(paginated_funcs)} functions")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_decompile(self, query):
            try:
                addr = query.get('addr', [''])[0]
                if not addr:
                    self.send_error(400, "Address parameter is required")
                    return
                decompiled = cutter.cmd(f"pdg @ {addr}")
                self.server.parent.signals.log_signal.emit(f"Decompiled function at {addr}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(decompiled.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_segments(self, query):
            try:
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                segments = cutter.cmd("iS").splitlines()
                result = segments[offset:offset+limit]
                response = "\n".join(result)
                self.server.parent.signals.log_signal.emit(f"Served {len(result)} segments")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_imports(self, query):
            try:
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                imports = cutter.cmd("ii").splitlines()
                result = imports[offset:offset+limit]
                response = "\n".join(result)
                self.server.parent.signals.log_signal.emit(f"Served {len(result)} imports")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_exports(self, query):
            try:
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                exports = cutter.cmd("iE").splitlines()
                result = exports[offset:offset+limit]
                response = "\n".join(result)
                self.server.parent.signals.log_signal.emit(f"Served {len(result)} exports")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_data(self, query):
            try:
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                data = cutter.cmd("pd 1000").splitlines()
                result = data[offset:offset+limit]
                response = "\n".join(result)
                self.server.parent.signals.log_signal.emit(f"Served {len(result)} data items")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_search_functions(self, query):
            try:
                search_term = query.get('query', [''])[0]
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                if not search_term:
                    self.send_error(400, "Search term is required")
                    return
                search_results = cutter.cmd(f"afl~{search_term}").splitlines()
                paginated_results = search_results[offset:offset+limit]
                response = "\n".join(paginated_results)
                self.server.parent.signals.log_signal.emit(
                    f"Found {len(search_results)} functions matching '{search_term}', "
                    f"returning {len(paginated_results)}"
                )
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error searching functions: {str(e)}")

        def handle_libraries(self, query):
            try:
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                libraries = cutter.cmd("ilq").splitlines()
                result = libraries[offset:offset+limit]
                response = "\n".join(result)
                self.server.parent.signals.log_signal.emit(f"Served {len(result)} libraries")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_headers(self, query):
            try:
                offset = int(query.get('offset', [0])[0])
                limit = int(query.get('limit', [100])[0])
                headers = cutter.cmd("i;iH").splitlines()
                result = headers[offset:offset+limit]
                response = "\n".join(result)
                self.server.parent.signals.log_signal.emit(f"Served {len(result)} headers")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(response.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_show_function_details(self, query):
            try:
                addr = query.get('addr', [''])[0]
                if not addr:
                    self.send_error(400, "Address parameter is required")
                    return
                functionDetail = cutter.cmd(f"afi @ {addr}")
                self.server.parent.signals.log_signal.emit(f"Served details about function at {addr}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(functionDetail.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_get_function_prototype(self, query):
            try:
                addr = query.get('addr', [''])[0]
                if not addr:
                    self.send_error(400, "Address parameter is required")
                    return
                functionPrototype = cutter.cmd(f"afs @ {addr}")
                self.server.parent.signals.log_signal.emit(f"Served signature of function at {addr}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(functionPrototype.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_xrefs_to(self, query):
            try:
                addr = query.get('addr', [''])[0]
                if not addr:
                    self.send_error(400, "Address parameter is required")
                    return
                xrefsTo = cutter.cmd(f"axt @ {addr}")
                self.server.parent.signals.log_signal.emit(f"Served references of code at {addr}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(xrefsTo.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_disassemble_function(self, query):
            try:
                addr = query.get('addr', [''])[0]
                if not addr:
                    self.send_error(400, "Address parameter is required")
                    return
                disassembledFunction = cutter.cmd(f"pdf @ {addr}")
                self.server.parent.signals.log_signal.emit(f"Disassembled function at {addr}")
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(disassembledFunction.encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error: {str(e)}")

        def handle_set_function_prototype(self, post_data):
            try:
                params = parse_qs(post_data.decode('utf-8'))
                address = params.get('address', [''])[0]
                description = params.get('description', [''])[0]

                if not address or not description:
                    self.send_error(400, "Both address and description parameters are required")
                    return

                cutter.cmd(f"afs {description} @ {address}")
                self.server.parent.signals.log_signal.emit(f"Set function signature at {address} to: {description}")

                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"Successfully set function signature at {address}".encode('utf-8'))
            except Exception as e:
                self.send_error(500, f"Error setting function signature: {str(e)}")
                                
    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        self.dock_widget = MCPDockWidget(main, self.signals)
        main.addPluginDockWidget(self.dock_widget)
        self.start_server()

    def start_server(self):
        if self.server is not None:
            self.signals.log_signal.emit("Server is already running!")
            return

        def run_server():
            server_address = ('', 8000)
            self.server = HTTPServer(server_address, self.MCPRequestHandler)
            self.server.parent = self
            self.signals.log_signal.emit("HTTP Server started at http://localhost:8000")
            self.signals.log_signal.emit("Available endpoints:")
            self.signals.log_signal.emit("GET /functions - List functions")
            self.signals.log_signal.emit("GET /decompile - Decompile function")
            self.signals.log_signal.emit("GET /segments - List memory segments")
            self.signals.log_signal.emit("GET /imports - List imports")
            self.signals.log_signal.emit("GET /exports - List exports")
            self.signals.log_signal.emit("GET /data - List defined data")
            self.signals.log_signal.emit("GET /searchFunctions - Search functions by name")
            self.signals.log_signal.emit("GET /libraries - List libraries")
            self.signals.log_signal.emit("GET /headers - Show headers")
            self.signals.log_signal.emit("GET /showFunctionDetails - Show details about function")
            self.signals.log_signal.emit("GET /getFunctionPrototype - Show signature of function")
            self.signals.log_signal.emit("GET /xrefsTo - List code references")
            self.signals.log_signal.emit("GET /disassembleFunction - Disassemble function")
            self.signals.log_signal.emit("POST /renameFunction - Rename a function")
            self.signals.log_signal.emit("POST /setDecompilerComment - Set decompiler comment")
            self.signals.log_signal.emit("POST /setFunctionPrototype - Set signature of function")
            self.server.serve_forever()

        self.server_thread = threading.Thread(target=run_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def terminate(self):
        if self.server:
            self.signals.log_signal.emit("Shutting down HTTP Server...")
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join()

def create_cutter_plugin():
    return MCPPlugin()
