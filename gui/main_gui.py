import sys
import os

# Adding project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk
from tkinter import filedialog
from tkinter import ttk
import ctypes
from analysis.taint_tracker import run_taint_analysis

#sharp text on Windows
ctypes.windll.shcore.SetProcessDpiAwareness(1)

#MAIN WINDOW 
root=tk.Tk()
root.title("Command Injection Detection Compiler (CIDC)")
root.geometry("1900x1120")
root.resizable(False,False)
root.configure(bg="#121212")

#STYLES
style=ttk.Style()
style.theme_use("clam")

style.configure("Blue.TButton",font=("Segoe UI",11),
    background="#3498db",foreground="white",padding=10,borderwidth=0)
style.map("Blue.TButton",background=[("active","#2980b9")])

style.configure("Green.TButton",font=("Segoe UI",11,"bold"),
    background="#27ae60",foreground="white",padding=10,borderwidth=0)
style.map("Green.TButton",background=[("active","#1e8449")])

style.configure("Gray.TButton",font=("Segoe UI",10),
    background="#424242",foreground="white",padding=8,borderwidth=0)
style.map("Gray.TButton",background=[("active","#616161")])

style.configure(
    "Dark.Vertical.TScrollbar",
    gripcount=0,
    background="#3a3a3a",
    darkcolor="#3a3a3a",
    lightcolor="#3a3a3a",
    troughcolor="#121212",
    bordercolor="#121212",
    arrowcolor="#121212"
)

style.map(
    "Dark.Vertical.TScrollbar",
    background=[
        ("active","#4a4a4a"),
        ("!active","#3a3a3a")
    ]
)


#HEADER
header=tk.Label(
    root,
    text="Command Injection Detection Compiler",
    font=("Segoe UI",20,"bold"),
    bg="#1f1f1f",
    fg="#00e5ff",
    pady=15
)
header.pack(fill=tk.X)

#MAIN CONTENT
main_frame=tk.Frame(root,bg="#121212")
main_frame.pack(fill=tk.BOTH,expand=True,padx=15,pady=15)

#LEFT PANEL (SOURCE CODE)
left_panel=tk.Frame(main_frame,bg="#1e1e1e",width=930)
left_panel.pack(side=tk.LEFT,fill=tk.Y,padx=(0,10))
left_panel.pack_propagate(False)

left_title=tk.Label(
    left_panel,
    text="Source Code",
    font=("Segoe UI",14,"bold"),
    bg="#1e1e1e",
    fg="white"
)
left_title.pack(pady=(10,5))

#Editor container
editor_container=tk.Frame(left_panel,bg="#1e1e1e")
editor_container.pack(fill=tk.BOTH,expand=True,padx=10,pady=5)
editor_scroll=ttk.Scrollbar(
    editor_container,
    orient=tk.VERTICAL,
    style="Dark.Vertical.TScrollbar"
)
editor_scroll.pack(side=tk.RIGHT,fill=tk.Y)

#Line numbers
line_numbers=tk.Text(
    editor_container,
    width=4,
    font=("Consolas",12),
    bg="#1a1a1a",
    fg="#888888",
    relief=tk.FLAT,
    state=tk.DISABLED,
    yscrollcommand=editor_scroll.set
)
line_numbers.pack(side=tk.LEFT,fill=tk.Y)

#Code editor
code_editor=tk.Text(
    editor_container,
    font=("Consolas",12),
    bg="#0d0d0d",
    fg="white",
    insertbackground="white",
    relief=tk.FLAT,
    yscrollcommand=editor_scroll.set
)
code_editor.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)

def sync_scroll(*args):
    code_editor.yview(*args)
    line_numbers.yview(*args)

editor_scroll.config(command=sync_scroll)

def sync_line_numbers():
    line_numbers.yview_moveto(code_editor.yview()[0])

#Line number update function
def update_line_numbers(event=None):
    line_numbers.config(state=tk.NORMAL)
    line_numbers.delete("1.0",tk.END)

    total_lines=int(code_editor.index("end-1c").split(".")[0])
    for i in range(1,total_lines+1):
        line_numbers.insert(tk.END,f"{i}\n")

    line_numbers.config(state=tk.DISABLED)
    sync_line_numbers()


#Bind updates
code_editor.bind("<KeyRelease>",update_line_numbers)
code_editor.bind("<ButtonRelease-1>",update_line_numbers)
def on_mousewheel(event):
    code_editor.yview_scroll(int(-1*(event.delta/120)),"units")
    line_numbers.yview_scroll(int(-1*(event.delta/120)),"units")
    return "break"

code_editor.bind("<MouseWheel>",on_mousewheel)
code_editor.bind("<Return>",update_line_numbers)
line_numbers.bind("<MouseWheel>",on_mousewheel)

left_buttons=tk.Frame(left_panel,bg="#1e1e1e")
left_buttons.pack(fill=tk.X,padx=10,pady=(5,10))

#RIGHT PANEL (ANALYSIS OUTPUT)
right_panel=tk.Frame(main_frame,bg="#1e1e1e",width=970)
right_panel.pack(side=tk.RIGHT,fill=tk.Y,padx=(10,0))
right_panel.pack_propagate(False)

right_title=tk.Label(
    right_panel,
    text="Analysis Output",
    font=("Segoe UI",14,"bold"),
    bg="#1e1e1e",
    fg="white"
)
right_title.pack(pady=(10,5))

#Output container
output_container=tk.Frame(right_panel,bg="#1e1e1e")
output_container.pack(fill=tk.BOTH,expand=True,padx=10,pady=5)

#Output scrollbar (dark)
output_scroll=ttk.Scrollbar(
    output_container,
    orient=tk.VERTICAL,
    style="Dark.Vertical.TScrollbar"
)
output_scroll.pack(side=tk.RIGHT,fill=tk.Y)

#Output text box
output_box=tk.Text(
    output_container,
    font=("Consolas",12),
    bg="#0d0d0d",
    fg="white",
    insertbackground="white",
    relief=tk.FLAT,
    yscrollcommand=output_scroll.set
)
output_box.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
output_box.config(state=tk.DISABLED)

#Connect scrollbar
output_scroll.config(command=output_box.yview)

#Output colors
output_box.tag_config("info",foreground="#64b5f6")
output_box.tag_config("input",foreground="#00e676")
output_box.tag_config("danger",foreground="#ff5252")
output_box.tag_config("success",foreground="#cfd8dc")

right_buttons=tk.Frame(right_panel,bg="#1e1e1e")
right_buttons.pack(fill=tk.X,padx=10,pady=(5,10))

#HELPER FUNCTIONS
def clear_output():
    output_box.config(state=tk.NORMAL)
    output_box.delete("1.0",tk.END)
    output_box.config(state=tk.DISABLED)

def write_output(text,tag=None):
    output_box.config(state=tk.NORMAL)
    if tag:
        output_box.insert(tk.END,text,tag)
    else:
        output_box.insert(tk.END,text)
    output_box.config(state=tk.DISABLED)
    output_box.see(tk.END)

#ACTIONS
def select_file():
    file_path=filedialog.askopenfilename(
        title="Select C/C++ Source File",
        filetypes=[("C Files","*.c"),("C++ Files","*.cpp")]
    )
    if file_path=="":
        return
    try:
        with open(file_path,"r") as f:
            code_editor.delete("1.0",tk.END)
            code_editor.insert(tk.END,f.read())
        update_line_numbers()
        status.config(text="Source code loaded")
    except:
        status.config(text="File read error")

def analyze_code():
    clear_output()
    write_output("Taint Analysis Results\n\n","info")
    
    code=code_editor.get("1.0",tk.END).splitlines()
    
    results=run_taint_analysis(code)
    
    for text,tag in results:
        write_output(text,tag)
    
    write_output("\nAnalysis completed successfully.","success")
    status.config(text="Analysis completed")


#BUTTONS
ttk.Button(
    left_buttons,
    text="Select C/C++ File",
    style="Blue.TButton",
    cursor="hand2",
    command=select_file
).pack(side=tk.LEFT)

ttk.Button(
    left_buttons,
    text="Clear Code",
    style="Gray.TButton",
    cursor="hand2",
    command=lambda: (code_editor.delete("1.0",tk.END),update_line_numbers())
).pack(side=tk.LEFT,padx=10)

ttk.Button(
    right_buttons,
    text="Analyze",
    style="Green.TButton",
    cursor="hand2",
    command=analyze_code
).pack(side=tk.LEFT)

ttk.Button(
    right_buttons,
    text="Clear Output",
    style="Gray.TButton",
    cursor="hand2",
    command=clear_output
).pack(side=tk.LEFT,padx=10)

#STATUS BAR
status=tk.Label(
    root,
    text="Ready",
    font=("Segoe UI",10),
    bg="#1f1f1f",
    fg="#b0bec5",
    anchor="w",
    padx=10
)
status.pack(fill=tk.X,side=tk.BOTTOM)

root.mainloop()