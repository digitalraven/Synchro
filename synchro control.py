from tkinter import *
import tkfiledialog
import os
import winreg
import win32com.client
import time
from subprocess import Popen

# FIXME: Put installation directory into HKLM rather than relying on AppData

class App:

    def __init__(self, master):
        frame = Frame(master)
        frame.pack()
        self.grid()
        self.createWidgets(master)
        self.su_var = IntVar()
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\Synchro\Config", 0, winreg.KEY_ALL_ACCESS) as k:
            i_path = winreg.QueryValueEx(k, "InstallDir")
        self.install_path = i_path[0]

    def createwidgets(self, master):
        
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\Synchro\Config") as k:
                dir1 = winreg.QueryValueEx(k, "dir1")[0]
                dir2 = winreg.QueryValueEx(k, "dir2")[0]
        except:
            dir1 = None
            dir2 = None
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\Microsoft\Windows\CurrentVersion\Run") as k:
                c = 1
        except:
            c = 0
        
        self.su_var.set(c)

        self.d1_lbl = Label(self, text="Directory").grid(row=1, column=0, columnspan=2, sticky=E)
        self.d1 = Entry(self, relief=SUNKEN).grid(row=1, column=2)
        self.d1_btn = Button(self, text="Browse", command=self.getdir).grid(row=1, column=4)
        self.d2_lbl = Label(self, text="Directory").grid(row=3, column=0, columnspan=2, sticky=E)
        self.d2 = Entry(self, relief=SUNKEN).grid(row=3, column=2)
        self.d2_btn = Button(self, text="Browse", command=self.getdir).grid(row=3, column=4)

        self.d1.insert(0, dir1)
        self.d2.insert(0, dir2)

        self.s_box = Checkbutton(self, text="Start Synchro when computer starts?", 
                                 variable=self.su_var).grid(row=5, column=0, columnspan=4, sticky=W)
        self.quit = Button(self, text="Exit", command=self.destroy).grid(row=6, column=0)
        self.save = Button(self, text="Save & Exit", command=self.saveExit).grid(row=6, column=2)
        self.save = Button(self, text="Save & Start", command=self.saveStart).grid(row=6, column=2)

    def startd(self):
        executable = os.path.join(self.install_path, "synchro_d.exe")
        if not os.path.exists(executable):
            messagebox.showerror("Missing File", "Daemon executable:\n\n" + executable + "\n\nNot found. Please reinstall.")
            raise IOError('Daemon executable not found!')
            self.destroy()
        # Kill process if open
        self.stopd()
        Popen(executable)
        messagebox.showinfo("Success", "Synchro is now running")
        self.destroy()
    
    def stopd(self):
        # this is a bit of a kludge until I work out how to tell the daemon to exit in a sensible way.
        
        # Return if not running
        if b'synchro_d.exe' not in Popen('tasklist', stdout=subprocess.PIPE).communicate()[0]:
            return

        # Kill process and record last-run time
        with open("NUL","w") as fh:
            t = str(time.time())
            Popen("taskkill /im synchro_d.exe", stdout = fh, stderr = fh)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            winreg.SetValueEx(k, "lastrun", 0, winreg.REG_SZ, t)

    def saveStart(self, master):
        try:
            self.saveconfig()
        except ValueError as e:
            messagebox.showerror("Error", "Directory does not exist.\n" + e)
            return
        else:
            self.startd()

    def saveExit():
        try:
            self.saveconfig()
        except ValueError as e:
            if not messagebox.askyesno("Error","Directory does not exist.\n" + e + "\n\nExit anyway?"):
                return
        self.destroy()

    def saveconfig(self, master):
        try:
            t_1 = self.check_type(self.d1.get())
            t_2 = self.check_type(self.d2.get())
        except ValueError as e:
             raise e

        # Open or create user config key
        path = "Software\Synchro\Config"
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS)
        except:
            k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, path)

        # Set config information
        try:
            winreg.SetValueEx(k, "dir1", 0, winreg.REG_SZ, self.d1.get())
            winreg.SetValueEx(k, "dir1_t", 0, winreg.REG_SZ, t1)
            winreg.SetValueEx(k, "dir2", 0, winreg.REG_SZ, self.d2.get())
            winreg.SetValueEx(k, "dir2_t", 0, winreg.REG_SZ, t2)
        except:
            messagebox.showerror("Error", "Could not save config.")

        # Set last run time to 0 if it doesn't exist
        try:
            winreg.QueryValueEx(k, "lastrun")
        except:
            winreg.SetValueEx(k, "lastrun", 0, winreg.REG_SZ, "0")

        winreg.CloseKey(k)

        # Set daemon to run on startup if selected.            
        path = "Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            try:
                check = winreg.QueryValueEx(k, "Synchro")
            except:
                check = False

            if (self.su_var.get() == 1) and not check:
                try:
                    winreg.SetValueEx(k, "Synchro", 0, winreg.REG_SZ, os.path.join(self.install_path, "synchro_d.exe"))
                except:
                    messagebox.showerror("Error", "Could not add Synchro to startup options.")
            elif (self.su_var.get() == 0) and check:
                try:
                    winreg.DeleteValue(k, "Synchro")
                except:
                    messagebox.showerror("Error", "Could not delete Synchro from startup options.")

    def check_type(self, dirname):
        # FIXME: Check directory type to see if ReadDirectoryChangesW is supported
        # Currently, assume so.
        if not os.path.exists(dirname):
            raise ValueError(str(dirname))

        return 0

def main():
    root = Tk()
    root.wm_title("Synchro Configuration")
    root.protocol("WM_DELETE_WINDOW", handler)
    app = App(root)
    root.mainloop()

def handler():
    if tkMessageBox.askokcancel("Quit?", "Are you sure you want to quit?"):
        root.quit()

if __name__ == "__main__":
    main()