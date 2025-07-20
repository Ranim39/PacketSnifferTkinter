from scapy.all import sniff,IP,TCP,UDP,Raw,wrpcap
from collections import Counter
from datetime import datetime
import tkinter as tk 
#The sniff() function from scapy blocks your program _meaning it runs forever( or until count or stop_filter )and freezes the rest , including your Tkinter GUI
#Thats why we need to create a new thread (background worker) so we let both run in parallel
import threading
#This line creates a Counter object from Python's built-in collections module
protocols=Counter()
sniffing=False #needs to click start button to start capture packets
captured_packets=[]

protocol_names ={6: 'TCP',17:'UDP',1:'ICMP'} #Known protocol numbers name map
def process_packet(packet):
    if not sniffing: #stop processing packets once the user clicks the "stop" button in the GUI
        return
    
    if IP in packet:
        src=packet[IP].src
        dst=packet[IP].dst
        proto_num=packet[IP].proto
        proto_name=protocol_names.get(proto_num,str(proto_num))
        time=datetime.now().strftime('%H:%M:%S')
        output=f"[{time}]{src}--->{dst} | Protocol: {proto_name}"
        if packet.haslayer(Raw):
            try:
                data=packet[Raw].load.decode(errors="ignore")
                output+=f"Payload:{data[:80]}...\n"
            except:
                output+="  Payload:[unreadable bytes]\n"
        output+="-" * 60 + "\n"
    text.insert(tk.END, output)
    #text.insert= adds a multi-line text box (Tkinter Text Widget) into the widget
    text.see(tk.END)
    #.see() makes sure a particular position inside the Text widget is visible (scrolled into view).
    protocols[proto_num]+=1 #like :protocols{6:7,17:2,1:1} /** 7 TCP packets (TCP=6) **/
    update_counts()
    captured_packets.append(packet)

#Update label with current protocol counts
def update_counts():
    text_str="Protocols: "
    for proto,count in protocols.items():
        name=protocol_names.get(proto,str(proto))
        text_str += f"{name}: {count}  "
    count_label.config(text=text_str)    #show some text

def sniff_thread():
    sniff(prn=process_packet, stop_filter=lambda x:not sniffing)


# Start sniffing (in background thread)
def start_sniffing():
    global sniffing
    sniffing=True
    t=threading.Thread(target=sniff_thread)
    t.start()

#we can filter by protocol(ex:only tcp):
#sniff(filter="tcp",prn=process_packet,count=5)

def stop_sniffing():
    global sniffing
    sniffing=False
    wrpcap("captured.pcap",captured_packets) #sniff packets and save them to captured.pcap
    text.insert(tk.END,"Sniffing stopped.Packets saved to captured.pcap\n")


#GUI setup

#root is the main window
root =tk.Tk()
root.title("Simple Packet Sniffer")
root.geometry("700x500")

#button_frame is a Frame widget packed at the bottom of root.
button_frame=tk.Frame(root)
button_frame.pack(side=tk.BOTTOM,pady=10)
#pady=10 :10 pixels to bottom around the widget
#tk.BOTH: widget expands both horizontally and vertically to fill all available space.

# Protocol counts label at the top
count_label=tk.Label(root,text="Protocols: ")
count_label.pack(side=tk.TOP,pady=10)

start_btn=tk.Button(button_frame,text ="Start Sniffing",width=15,command=start_sniffing)
start_btn.pack(side=tk.LEFT,padx=10)

stop_btn=tk.Button(button_frame,text ="Stop Sniffing",width=15,command=stop_sniffing)
stop_btn.pack(side=tk.LEFT,padx=10)

text=tk.Text(root,font=("Consolas",10))
text.pack(expand=True,fill=tk.BOTH,padx=10,pady=(0,10))


root.mainloop()