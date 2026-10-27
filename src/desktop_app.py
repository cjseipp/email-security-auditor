import tkinter as tk
from tkinter import ttk,messagebox,filedialog
from threading import Thread
from audit_engine import audit
from reporting import package

root=tk.Tk();root.title('Cyber Ready Email Security Auditor');root.geometry('780x570')
frame=ttk.Frame(root,padding=20);frame.pack(fill='both',expand=True)
ttk.Label(frame,text='Email Security Reassessment',font=('Segoe UI',18,'bold')).pack(anchor='w')
ttk.Label(frame,text='Read-only public DNS checks. No PowerShell or Python commands needed.').pack(anchor='w',pady=(3,14))
entry=ttk.Entry(frame,font=('Segoe UI',12));entry.insert(0,'buktech.com');entry.pack(fill='x')
selector=ttk.Entry(frame);ttk.Label(frame,text='DKIM selector (optional, if provided by your email administrator)').pack(anchor='w',pady=(12,2));selector.pack(fill='x')
status=tk.StringVar(value='Ready to assess.');ttk.Label(frame,textvariable=status).pack(anchor='w',pady=10)
output=tk.Text(frame,wrap='word',height=17);output.pack(fill='both',expand=True)

def start():
    button.config(state='disabled');status.set('Checking public DNS records...')
    domain=entry.get();sel=selector.get().strip()
    def job():
        try:
            result=audit(domain,dkim_selector=sel)
            zipfile=package(result)
            message='\n'.join(f'{x["control"]}: {x["severity"]}\n{x["observation"]}\nAction: {x["recommendation"]}\n' for x in result['findings'])
            root.after(0,lambda:finish(message,str(zipfile),None))
        except Exception as e:root.after(0,lambda err=str(e):finish('',None,err))
    Thread(target=job,daemon=True).start()

def finish(message,zipfile,error):
    button.config(state='normal')
    if error:status.set('Assessment failed');messagebox.showerror('Assessment error',error);return
    output.delete('1.0','end');output.insert('end',message)
    status.set('Assessment complete. Client package saved to: '+zipfile)
    messagebox.showinfo('Complete','Your client report ZIP is ready:\n'+zipfile)
button=ttk.Button(frame,text='Run Assessment and Create Client Package',command=start);button.pack(pady=10)
root.mainloop()
