#
# This is a CSV reader specifically designed for NetFlow records.
# It allows users to select a CSV file to read and create filters 
# for specific protocols.
#
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import os
import sys
import subprocess

# --- MultiSelectFilterDialog Class ---
class MultiSelectFilterDialog(tk.Toplevel):
    def __init__(self, parent_app, column_name, all_unique_values, initial_selected_values):
        super().__init__(parent_app.master)
        self.parent_app = parent_app
        self.column_name = column_name
        # Sort values for consistent display and easier navigation
        self.all_unique_values = sorted(list(all_unique_values)) 
        # Copy to preserve original state if user cancels
        self.initial_selected_values = initial_selected_values.copy() 
        # Current state of selections in the dialog
        self.selected_values = initial_selected_values.copy() 

        self.title(f"Filter {column_name}")
        self.geometry("400x500")
        self.transient(parent_app.master) # Make it appear on top of the main window
        self.grab_set() # Make it modal, blocking interaction with parent

        self.checkbox_vars = {} # Stores tk.BooleanVar for each value

        # Search / Filter Entry for the dialog itself
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self.update_list_display)
        search_frame = ttk.Frame(self)
        search_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side="left", padx=5)
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side="left", expand=True, fill="x")

        # Treeview for checkboxes and values
        tree_frame = ttk.Frame(self)
        tree_frame.pack(expand=True, fill="both", padx=10, pady=5)

        self.tree = ttk.Treeview(tree_frame, columns=("Selected", "Value"), show="headings")
        self.tree.heading("Selected", text="✔", anchor="center")
        self.tree.heading("Value", text=column_name, anchor="w")
        self.tree.column("Selected", width=30, anchor="center", stretch=tk.NO)
        self.tree.column("Value", width=300, anchor="w", stretch=tk.NO) # Added stretch=tk.NO
        self.tree.pack(side="left", expand=True, fill="both")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.bind("<Button-1>", self.on_tree_click) # Bind click event for checkboxes

        self.populate_treeview() # Initial population

        # Buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=5)

        ttk.Button(button_frame, text="Select All", command=self.select_all).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Deselect All", command=self.deselect_all).pack(side="left", padx=2)
        ttk.Button(button_frame, text="Apply", command=self.on_apply).pack(side="right", padx=2)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side="right", padx=2)

    def populate_treeview(self):
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.checkbox_vars.clear()

        search_text = self.search_var.get().lower()

        for val in self.all_unique_values:
            if search_text and search_text not in str(val).lower():
                continue # Skip if it doesn't match search filter

            # Initialize BooleanVar and set its initial state
            var = tk.BooleanVar(value=(val in self.selected_values))
            self.checkbox_vars[val] = var
            
            # Display a checkmark or empty string based on var's value
            display_check = "✔" if var.get() else ""
            self.tree.insert("", "end", iid=val, values=(display_check, val))

    def update_list_display(self, *args):
        self.populate_treeview() # Re-populate treeview based on search

    def on_tree_click(self, event):
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return

        column = self.tree.identify_column(event.x)
        if column == "#1": # Clicked on the "Selected" column (the checkbox column)
            val = item_id # The iid is the actual value we stored
            var = self.checkbox_vars.get(val)
            if var:
                var.set(not var.get()) # Toggle the BooleanVar
                if var.get():
                    self.selected_values.add(val) # Add to selected set
                else:
                    self.selected_values.discard(val) # Remove from selected set
                self.tree.item(item_id, values=("✔" if var.get() else "", val)) # Update display

    def select_all(self):
        for val in self.all_unique_values:
            # Only affect items currently displayed (matching search filter)
            if self.search_var.get().lower() in str(val).lower(): 
                self.checkbox_vars[val].set(True)
                self.selected_values.add(val)
        self.populate_treeview() # Refresh display

    def deselect_all(self):
        for val in self.all_unique_values:
            # Only affect items currently displayed (matching search filter)
            if self.search_var.get().lower() in str(val).lower(): 
                self.checkbox_vars[val].set(False)
                self.selected_values.discard(val)
        self.populate_treeview() # Refresh display

    def on_apply(self):
        # Pass the final selected values back to the parent app
        self.parent_app.apply_multi_filters(self.column_name, self.selected_values)
        self.destroy()

# --- CSVViewerApp Class ---
class CSVViewerApp:
    def __init__(self, master):
        self.master = master
        master.title("CSV File Viewer")
        master.geometry("1200x700") # Adjusted initial size for more columns
        master.resizable(width=True, height=True)

        self.current_file_path = None
        self.all_data = [] # Stores all rows from the CSV, including headers
        self.column_headers = [] # Stores the headers as a list
        
        # Columns for which we want multi-select filters
        # Added "ICMP Type" for potential filtering
        self.filterable_columns = ["Protocol", "Source IP", "Destination IP", "ICMP Type"] 
        
        # Stores unique values found in each filterable column
        self.unique_column_values = {col: set() for col in self.filterable_columns}
        
        # Stores the currently selected filter values for each column (sets of values)
        self.active_filters = {col: set() for col in self.filterable_columns}

        # --- Widgets ---
        control_frame = tk.Frame(master)
        control_frame.pack(pady=10)

        self.select_button = tk.Button(control_frame, text="Select CSV File", command=self.open_csv_file, height=2)
        self.select_button.pack(side="left", padx=5)

        # Filter buttons for each filterable column
        self.filter_buttons = {}
        for col in self.filterable_columns:
            # Using lambda with default argument to capture current 'col' value
            btn = tk.Button(control_frame, text=f"Filter {col}", command=lambda c=col: self.open_multi_select_filter_dialog(c), height=2, state=tk.DISABLED)
            btn.pack(side="left", padx=5)
            self.filter_buttons[col] = btn
        
        self.clear_all_filters_button = tk.Button(control_frame, text="Clear All Filters", command=self.clear_all_filters, height=2, state=tk.DISABLED)
        self.clear_all_filters_button.pack(side="left", padx=5)

        self.file_label = tk.Label(master, text="No file selected", wraplength=900)
        self.file_label.pack(pady=5)

        # Frame for Treeview and Scrollbar
        tree_frame = ttk.Frame(master)
        tree_frame.pack(expand=True, fill="both", padx=10, pady=10)

        # Scrollbars for Treeview - pack them first to reserve space
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side="bottom", fill="x")

        # Treeview (Table) - pack it last to fill the remaining space
        self.tree = ttk.Treeview(tree_frame, show="headings")
        self.tree.pack(expand=True, fill="both") 
        
        # Configure Treeview to use the scrollbars
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.config(command=self.tree.yview) # Explicitly link scrollbar to treeview
        hsb.config(command=self.tree.xview) # Explicitly link scrollbar to treeview

        # Quit button
        self.quit_button = tk.Button(master, text="Quit", command=master.quit, fg="red", height=2)
        self.quit_button.pack(pady=10)

    def open_csv_file(self):
        file_path = filedialog.askopenfilename(
            initialdir=os.getcwd(),
            title="Select a CSV file",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*"))
        )

        if file_path:
            self.current_file_path = file_path
            self.file_label.config(text=f"Selected file: {os.path.basename(file_path)}")
            self.load_csv_data(file_path)
            # Enable filter buttons after data is loaded
            for btn in self.filter_buttons.values():
                btn.config(state=tk.NORMAL)
            self.clear_all_filters_button.config(state=tk.NORMAL)
        else:
            self.file_label.config(text="No file selected")
            # Disable filter buttons if no file selected
            for btn in self.filter_buttons.values():
                btn.config(state=tk.DISABLED)
            self.clear_all_filters_button.config(state=tk.DISABLED)
            self.all_data = []
            self.column_headers = []
            self.unique_column_values = {col: set() for col in self.filterable_columns}
            self.active_filters = {col: set() for col in self.filterable_columns}
            self._repopulate_treeview() # Clear treeview if file selection is cancelled

    def load_csv_data(self, file_path):
        self.all_data = []
        self.column_headers = []
        # Reset unique values and active filters for the new file
        self.unique_column_values = {col: set() for col in self.filterable_columns}
        self.active_filters = {col: set() for col in self.filterable_columns}

        try:
            with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                
                try:
                    self.column_headers = next(reader)
                    self.all_data.append(self.column_headers) # Store headers as the first row in all_data
                except StopIteration:
                    messagebox.showwarning("Empty File", "The selected CSV file is empty or has no headers.")
                    return

                # Determine column indices for filterable columns
                col_indices = {}
                for col in self.filterable_columns:
                    try:
                        col_indices[col] = self.column_headers.index(col)
                    except ValueError:
                        # If a filterable column is not found, print a warning but continue
                        print(f"Warning: Filterable column '{col}' not found in CSV headers. It will be ignored for filtering.")

                for row in reader:
                    self.all_data.append(row)
                    # Collect unique values for filterable columns
                    for col_name, idx in col_indices.items():
                        if idx < len(row): # Ensure index is valid for the current row
                            self.unique_column_values[col_name].add(row[idx])
            
            self._repopulate_treeview() # Populate treeview with all data initially
            
        except FileNotFoundError:
            messagebox.showerror("Error", f"File not found: {file_path}")
            self.file_label.config(text="Error: File not found")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while reading the CSV file: {e}")
            self.file_label.config(text=f"Error reading file: {e}")
        
    def open_multi_select_filter_dialog(self, column_name):
        if not self.column_headers:
            messagebox.showwarning("No Data", "Please load a CSV file first to apply filters.")
            return
        
        # Check against the full set of headers from the file, not just display_column_headers
        if column_name not in self.column_headers:
            messagebox.showwarning("Column Not Found", f"The column '{column_name}' was not found in the loaded CSV headers. Cannot filter.")
            return

        all_values = self.unique_column_values.get(column_name, set())
        current_selection = self.active_filters.get(column_name, set())
        
        MultiSelectFilterDialog(self, column_name, all_values, current_selection)

    def apply_multi_filters(self, column_name, selected_values_set):
        # Update the active filters for the specific column
        self.active_filters[column_name] = selected_values_set
        self._repopulate_treeview()

    def clear_all_filters(self):
        for col in self.filterable_columns:
            self.active_filters[col] = set() # Clear all selections
        self._repopulate_treeview()
        messagebox.showinfo("Filters Cleared", "All filters have been cleared.")


    def _repopulate_treeview(self):
        # Clear existing data in the treeview
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Clear existing columns
        self.tree["columns"] = ()

        if not self.column_headers:
            return # No headers, nothing to display

        # Define columns to display and their order
        # Exclude "Next Hop" and "DSCP"
        all_possible_headers = [
            "Timestamp", "Source IP", "Destination IP", "Next Hop", "Interface Name",
            "DSCP", "Protocol", "Bytes", "Packets", "Source Port", "Destination Port",
            "ICMP Type", "ICMP Code", "ICMP Description"
        ]
        
        display_column_headers = [
            header for header in all_possible_headers 
            if header in self.column_headers and header not in ["Next Hop", "DSCP"]
        ]

        # Map original column indices to display column indices
        original_header_to_index = {header: i for i, header in enumerate(self.column_headers)}
        
        # Configure Treeview columns with display headers
        self.tree["columns"] = display_column_headers
        for col_name in display_column_headers:
            self.tree.heading(col_name, text=col_name, anchor="w")
            
            # Set specific widths for known columns, and ensure stretch=tk.NO
            if col_name == "Timestamp":
                self.tree.column(col_name, width=220, anchor="w", stretch=tk.NO)
            elif col_name == "Source IP":
                self.tree.column(col_name, width=170, anchor="w", stretch=tk.NO)
            elif col_name == "Destination IP": # Resized
                self.tree.column(col_name, width=170, anchor="w", stretch=tk.NO)
            elif col_name == "ICMP Type":
                self.tree.column(col_name, width=120, anchor="w", stretch=tk.NO)
            elif col_name == "ICMP Code":
                self.tree.column(col_name, width=100, anchor="w", stretch=tk.NO)
            elif col_name == "ICMP Description": # Resized
                self.tree.column(col_name, width=250, anchor="w", stretch=tk.NO)
            else:
                # Default width for other columns, also with stretch=tk.NO
                self.tree.column(col_name, width=max(100, len(col_name) * 10), anchor="w", stretch=tk.NO) 

        # Insert filtered data rows
        # Start from 1 to skip the header row in self.all_data
        for row_index, row_data_from_file in enumerate(self.all_data[1:]): 
            if self._row_matches_filters(row_data_from_file):
                # Prepare the row for display based on display_column_headers
                values_for_display = []
                for col_name in display_column_headers:
                    original_idx = original_header_to_index.get(col_name)
                    if original_idx is not None and original_idx < len(row_data_from_file):
                        values_for_display.append(row_data_from_file[original_idx])
                    else:
                        values_for_display.append("") # Should not happen if headers are consistent

                self.tree.insert("", "end", values=values_for_display)

    def _row_matches_filters(self, row):
        # Iterate through each filterable column
        for col_name in self.filterable_columns:
            filter_set = self.active_filters.get(col_name)
            
            # If the filter set is empty, it means no filter is applied for this column, so it matches
            if not filter_set:
                continue

            try:
                col_index = self.column_headers.index(col_name)
                # Get the value from the current row for the filterable column
                row_value = str(row[col_index])
                
                # If the row's value is NOT in the selected filter set, this row does not match
                if row_value not in filter_set:
                    return False
            except ValueError:
                # If a filterable column is not in the headers of the loaded CSV,
                # we treat it as not matching the filter for that specific column.
                # Or, more practically, if the filterable column is not in the CSV,
                # the filter on it effectively does nothing. For now, we'll assume
                # if the column isn't there, it can't match the filter.
                return False 
            except IndexError:
                # Row is shorter than expected, cannot check this column.
                return False

        return True # All active filters matched

if __name__ == "__main__":
    # --- Self-backgrounding logic ---
    if "--detached" not in sys.argv:
        script_path = os.path.abspath(__file__)
        command = [sys.executable, script_path, "--detached"]

        if sys.platform == "win32":
            creationflags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            subprocess.Popen(command, creationflags=creationflags, close_fds=True)
        else: # Unix-like systems (Linux, macOS)
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(command, stdout=devnull, stderr=devnull,
                                 start_new_session=True, close_fds=True)
        
        print("CSV Viewer GUI launched in the background.")
        sys.exit(0) # Exit the parent process immediately, releasing the terminal

    # If we reach here, it means this process was launched with --detached
    # and should proceed with normal GUI initialization.
    root = tk.Tk()
    app = CSVViewerApp(root)
    root.mainloop()
