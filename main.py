from PyQt5.QtCore import *
from PyQt5.QtWidgets import QMainWindow,QApplication,QPushButton,QFileDialog,QFileSystemModel,QGraphicsView,QGraphicsPixmapItem,QMessageBox
from PyQt5 import uic
from mainui import *
from PyQt5.QtGui import QPixmap
from PIL import Image
import os,resourcecode,sys,numpy as np,PyPDF2,datetime,hashlib,glob,subprocess,requests,zipfile
from PyQt5.QtCore import QThread, pyqtSignal
from PIL import Image
from tqdm import tqdm
# output_directory = "datarecovery"
from threading import Thread
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QMessageBox, QComboBox, QHBoxLayout, QProgressBar, QFileDialog
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5 import uic
from PyQt5.QtGui import QPixmap, QIcon
from mutagen.mp3 import MP3
from mutagen.id3 import ID3
from datetime import datetime
from bs4 import BeautifulSoup
from PyQt5.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem, QWidget, QVBoxLayout


virusnamewithtype=[]
virusname = []

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        #to import the ui file
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setFixedSize(1600,900)
        self.setWindowTitle("CyberFox")
        self.setWindowIcon(QIcon('logo.png'))

        with open('maincss.css', 'r') as style:
            self.setStyleSheet(style.read())

        #to set the initial index of ui to default
        self.ui.contentviewstacked.setCurrentIndex(0)
        self.ui.resultviewstacke.setCurrentIndex(1)



        #normal tree view file funtion
        self.file_system_model=QFileSystemModel(self.ui.uuuuuuuuuuuuuuuu)
        self.file_system_model.setRootPath("")
        self.file_system_model.setNameFilters(['*'])
        self.file_system_model.setNameFilterDisables(False)
        self.ui.tree_view.setModel(self.file_system_model)
        self.ui.tree_view.setRootIndex(self.file_system_model.index(""))
        self.ui.tree_view.setColumnWidth(0,250)
        self.ui.tree_view.setHeaderHidden(False)


        self.ui.stegnographyselectionpb.clicked.connect(self.when_steg_mode_slected)
        self.ui.backtotreeviewpb.clicked.connect(self.when_backtotreeviewpb_clicked)
        self.ui.customstegpb.clicked.connect(self.when_cuctomstegpb_clicked)
        self.ui.automatedstegscanpb.clicked.connect(self.when_automatedstegscanclicked)



        self.ui.datarecovryoption.clicked.connect(self.when_datarecoeryoption_clicked)
        self.ui.jpgrecoverypushbutton.clicked.connect(self.when_jpgrecovrypb_clicked)
        self.recovery_thread = None
        self.ui.recoverystopbtn.clicked.connect(self.when_stoprecoveryclicked)
        self.ui.selectlocationpb.clicked.connect(self.when_slectlocationb_clicked)
        self.output_directory = "datarecovery"


        self.ui.bruteforce_selectionpb.clicked.connect(self.when_bruteforcepb_clicked)

        self.ui.select_rarfile.clicked.connect(self.when_select_rarfilepb_clicked)
        self.ui.select_passwordlistpb.clicked.connect(self.when_select_passwordlistpb_clicked)
        self.ui.brutefore_attackpb.clicked.connect(self.when_bruteforce_attacked_clicked)
        self.ui.bruteforce_stoppb.clicked.connect(self.when_bruteforce_stopclicked)
        self.wordlist = "output.txt"
        self.zip_file = ""
        self.zip_file_object = None
        self.stop_attack = False
        self.ui.bruteforce_stoppb.setEnabled(False)
        self.ui.brutefore_attackpb.setEnabled(False)

        self.ui.custompassword_generatepb.clicked.connect(self.when_custompasspb_clicked)

        self.ui.custompassword_generatebtn.clicked.connect(self.when_custompassword_generatebtnCLicked)
        self.words = []
        self.ui.custompasswordinput_lineedit.returnPressed.connect(self.add_word)

        self.ui.malwareanalysis_slectionpb.clicked.connect(self.when_malwareanalysisselection_pbclicked)

        self.ui.malware_customscan_pb.clicked.connect(self.when_malware_cutomscanpbclicked)
        self.ui.malwareanalysis_stopbtn.setEnabled(False)
        self.ui.malwareanalysis_stopbtn.clicked.connect(self.stop_scan)
        self.ui.malware_filescanpb.clicked.connect(self.when_malwarefilescan_clicked)

        #hashcracker
        self.ui.hashcrackerselection_pb.clicked.connect(self.when_hashcrackerserlction_pb_clicked)
        self.ui.hashcraker_combobox.addItems(['MD5','SHA 1',"SHA 256","SHA 512"])
        self.hashcraker_selectedfile=""
        self.ui.hashcracker_selectfilepb.clicked.connect(self.hashcracker_selectfile)
        self.ui.hashcracker_crackfilepb.clicked.connect(self.hashcracker_crackhash)
        self.ui.hashcracker_stoppb.clicked.connect(self.hashcracker_stop_cracking)

        #hashcalc
        self.ui.hashcalcselction_pb.clicked.connect(self.when_hashcalcselectionpb_clicked)
        self.ui.hashcalc_textedit.textChanged.connect(self.calculate_hashes)

        #hexview
        self.set_hexviewbutton_enabled(False)
        self.ui.tree_view.clicked.connect(self.if_hexview_item_clicked)
        self.ui.hexviewpb.clicked.connect(self.when_hexviewpb_clicked)
        self.ui.textviewpb.clicked.connect(self.when_textviewpb_clicked)
        self.ui.mediaviewpb.clicked.connect(self.when_mediaviewpb_clicked)


        #tree view
        file_types_item = QTreeWidgetItem(self.ui.treeWidget, ['File Types'])
        audio_item = QTreeWidgetItem(file_types_item, ['Audio'])
        videos_item = QTreeWidgetItem(file_types_item, ['Videos'])
        images_item = QTreeWidgetItem(file_types_item, ['Images'])
        documents_item = QTreeWidgetItem(file_types_item, ['Documents'])
        #

        #recent audios
        mp3_files = self.find_limited_mp3_files()
        self.add_sub_items(audio_item, mp3_files)

        #recent videos
        video_files = self.find_limited_video_files()
        self.add_sub_items(videos_item, video_files)
        #recent images
        image_files = self.find_limited_image_files()
        self.add_sub_items(images_item, image_files)

        # Find limited document files for Documents
        doc_files = self.find_limited_document_files()
        self.add_sub_items(documents_item, doc_files)

        # Create top level item "Web History"
        web_history_item = QTreeWidgetItem(self.ui.treeWidget, ['Web History'])
        self.add_web_history_sub_items(web_history_item)

        installed_programs_item = QTreeWidgetItem(self.ui.treeWidget, ['Installed Programs'])
        self.add_installed_programs_sub_items(installed_programs_item)

        # Create top level item "Recent Activities"
        recent_activities_item = QTreeWidgetItem(self.ui.treeWidget, ['Recent Activities'])
        self.add_recent_activities_sub_items(recent_activities_item)
        # Create top level item "Web Downloads
        web_downloads_item = QTreeWidgetItem(self.ui.treeWidget, ['Web Downloads'])
        self.add_web_downloads_sub_items(web_downloads_item)

    def add_web_downloads_sub_items(self, parent_item):
        downloads_folder = os.path.expanduser('~/Downloads')
        if os.path.exists(downloads_folder) and os.path.isdir(downloads_folder):
            download_files = glob.glob(os.path.join(downloads_folder, '*'))
            for download_file in download_files:
                if os.path.isfile(download_file):
                    file_name = os.path.basename(download_file)
                    sub_item = QTreeWidgetItem(parent_item, [file_name])
                    sub_item.setToolTip(0, download_file)  # Set tooltip to file path

    def add_recent_activities_sub_items(self, parent_item):
        def list_items_in_folder(folder_path):
            try:
                # Check if the path exists
                if not os.path.exists(folder_path):
                    print("Folder path does not exist.")
                    return []

                # List all items in the folder
                items = os.listdir(folder_path)
                item_list = []

                # Append each item to the list
                for item in items:
                    item_path = os.path.join(folder_path, item)
                    # Check if the item is a directory
                    if os.path.isdir(item_path):
                        item_list.append(f"Directory: {item}")
                    else:
                        item_list.append(f"File: {item}")
                return item_list
            except Exception as e:
                print("An error occurred:", e)
                return []

        # Folder path for Recent Items
        recent_items_path = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Recent')

        # Call the function to list items in the Recent Items folder
        recent_activities = list_items_in_folder(recent_items_path)
        self.add_sub_items(parent_item, [{"name": activity, "path": os.path.join(recent_items_path, activity)}
                                         for activity in recent_activities])

    def add_installed_programs_sub_items(self, parent_item):
        installed_programs = self.get_installed_programs()
        self.add_sub_items(parent_item, installed_programs)

    def get_installed_programs(self):
        installed_programs = []
        try:
            # Get the installed programs using subprocess
            data = subprocess.check_output(['wmic', 'product', 'get', 'name'])
            programs = data.decode('utf-8').split('\n')[1:]
            for program in programs:
                if program.strip():
                    installed_programs.append({"name": program.strip()})
        except subprocess.CalledProcessError as e:
            print("Error getting installed programs:", e)
        return installed_programs
    def get_web_links(self):
        url = "https://www.yahoo.com/"
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            links = soup.find_all('a')
            web_links = [{"name": link.get('href'), "path": ""} for link in links[:8]]  # Limit to 8 links
            return web_links
        else:
            print("Failed to fetch web links:", response.status_code)
            return []

    def add_web_history_sub_items(self, parent_item):
        web_links = self.get_web_links()
        self.add_sub_items(parent_item, web_links)
    def find_limited_image_files(self):
        image_files = []
        home_dir = os.path.expanduser('~')
        image_paths = glob.glob(os.path.join(home_dir, '**/*.jpg'), recursive=True) + \
                      glob.glob(os.path.join(home_dir, '**/*.png'), recursive=True)  # jpg and png for images
        for image_path in image_paths[:4]:  # Limit to first 4 image files
            image_name = os.path.basename(image_path)
            image_files.append({"name": image_name, "path": image_path})
        return image_files

    def find_limited_document_files(self):
        doc_files = []
        home_dir = os.path.expanduser('~')
        doc_paths = glob.glob(os.path.join(home_dir, '**/*.pdf'), recursive=True) + \
                    glob.glob(os.path.join(home_dir, '**/*.docx'), recursive=True)  # pdf and docx for documents
        for doc_path in doc_paths[:4]:  # Limit to first 4 document files
            doc_name = os.path.basename(doc_path)
            doc_files.append({"name": doc_name, "path": doc_path})
        return doc_files
    def find_limited_video_files(self):
        video_files = []
        home_dir = os.path.expanduser('~')
        video_paths = glob.glob(os.path.join(home_dir, '**/*.mp4'), recursive=True)
        for video_path in video_paths[:4]:  # Limit to first 4 video files
            video_name = os.path.basename(video_path)
            video_files.append({"name": video_name, "path": video_path})
        return video_files

    def add_sub_items(self, parent_item, items):
        for item in items:
            name = item["name"]
            if parent_item.text(0) in ["Web History", "Recent Activities", "Installed Programs", "Web Downloads"]:
                tooltip = name  # Set tooltip to the item's name
            else:
                tooltip = item.get("path", name)  # Get the path from the item, default to name if not found
            sub_item = QTreeWidgetItem(parent_item, [name])
            sub_item.setToolTip(0, tooltip)  # Set tooltip to path or name


    def find_limited_mp3_files(self):
        mp3_files = []
        home_dir = os.path.expanduser('~')
        mp3_paths = glob.glob(os.path.join(home_dir, '**/*.mp3'), recursive=True)
        for mp3_path in mp3_paths[:4]:  # Limit to first 4 MP3 files
            mp3_name = os.path.basename(mp3_path)
            mp3_files.append({"name": mp3_name, "path": mp3_path})
        return mp3_files

    def when_mediaviewpb_clicked(self):
        selected_index = self.ui.tree_view.currentIndex()
        selected_path = self.file_system_model.filePath(selected_index)
        pixmap = QPixmap(selected_path)
        if pixmap.isNull():
            print("Failed to load image.")
            return
        self.ui.textEdit.clear()  # Clear existing content
        html = f'<img src="{selected_path}" width="{self.ui.textEdit.width()}" />'
        self.ui.textEdit.setHtml(html)


    def cssloader(filename):
        with open(filename,'r') as rd:
            content = rd.read()
            rd.close()
        return content
    def is_media_file(self, file_path):
        media_extensions = ['.png', '.jpg', '.jpeg', '.bmp', '.gif']
        for ext in media_extensions:
            if file_path.lower().endswith(ext):
                return True
        return False
    def is_text_file(self, file_path):
        text_extensions = ['.txt', '.csv', '.py', '.html', '.css', '.js']  # Add more extensions as needed
        for ext in text_extensions:
            if file_path.lower().endswith(ext):
                return True
        return False

    def when_textviewpb_clicked(self):
        selected_index = self.ui.tree_view.currentIndex()
        text_file_path = self.file_system_model.filePath(selected_index)
        try:
            with open(text_file_path, 'r', encoding='utf-8') as file:
                text_content = file.read()
                self.ui.textEdit.setPlainText(text_content)
        except Exception as e:
            print(f"Error reading text file: {str(e)}")
    def when_hexviewpb_clicked(self):
        selected_index = self.ui.tree_view.currentIndex()
        selected_path = self.file_system_model.filePath(selected_index)

        try:
            with open(selected_path, 'rb') as file:
                hex_content = file.read()
                hex_str = ""
                ascii_str = ""
                for i, byte in enumerate(hex_content):
                    hex_str += f"{byte:02X} "
                    ascii_str += chr(byte) if 32 <= byte <= 126 else '.'
                    if (i + 1) % 16 == 0:
                        hex_str += '  '
                        hex_str += ascii_str
                        hex_str += '\n'
                        ascii_str = ""
                # Add the remaining ASCII characters if the last line is not complete
                if ascii_str:
                    hex_str += '   ' * (16 - len(ascii_str))
                    hex_str += ascii_str
                self.ui.textEdit.setPlainText(hex_str)
        except Exception as e:
            print(f"Error reading file in hex view: {str(e)}")


    def when_backtotreeviewpb_clicked(self):

        self.ui.contentviewstacked.setCurrentIndex(0)
        self.ui.resultviewstacke.setCurrentIndex(1)
        buttons = [self.ui.backtotreeviewpb, self.ui.stegnographyselectionpb, self.ui.datarecovryoption,self.ui.bruteforce_selectionpb,self.ui.malwareanalysis_slectionpb,self.ui.hashcrackerselection_pb,self.ui.hashcalcselction_pb]
        for button in buttons:
            if button is not self.ui.backtotreeviewpb:
                button.setChecked(False)
            else:
                button.setChecked(True)

    def set_hexviewbutton_enabled(self, status):
        self.ui.hexviewpb.setEnabled(status)
        self.ui.textviewpb.setEnabled(status)
        self.ui.mediaviewpb.setEnabled(status)
    def if_hexview_item_clicked(self, index):
        file_path = self.file_system_model.filePath(index)
        # self.status_label.setText('Selected Item: ' + file_path)
        if os.path.isfile(file_path):
            self.set_hexviewbutton_enabled(True)
        else:
            self.set_hexviewbutton_enabled(False)
    def when_hashcalcselectionpb_clicked(self):
        self.ui.contentviewstacked.setCurrentIndex(7)
        self.ui.resultviewstacke.setCurrentIndex(8)
        self.calculate_hashes()
        buttons = [self.ui.backtotreeviewpb, self.ui.stegnographyselectionpb, self.ui.datarecovryoption,self.ui.bruteforce_selectionpb,self.ui.malwareanalysis_slectionpb,self.ui.hashcrackerselection_pb,self.ui.hashcalcselction_pb]
        for button in buttons:
            if button is not self.ui.hashcalcselction_pb:
                button.setChecked(False)
            else:
                button.setChecked(True)

    def calculate_hashes(self):
        text = self.ui.hashcalc_textedit.toPlainText()
        hash_results = self.calculate_hashes_for_text(text)

        result_text = "Hash results:\n"
        for algorithm, hash_value in hash_results.items():
            result_text += f"Hash ({algorithm}): {hash_value}\n"

        self.ui.hashcalcresultlabel.setText(result_text)

    def calculate_hashes_for_text(self, text):
        hash_results = {}
        for algorithm in hashlib.algorithms_guaranteed:
            try:
                if algorithm.startswith("shake_"):
                    bits = int(algorithm.split("_")[1])
                    hash_func = hashlib.shake_128() if bits == 128 else hashlib.shake_256()
                    hash_func.update(text.encode('utf-8'))
                    hash_value = hash_func.hexdigest(16)
                else:
                    hash_func = hashlib.new(algorithm)
                    hash_func.update(text.encode('utf-8'))
                    hash_value = hash_func.hexdigest()
                hash_results[algorithm] = hash_value
            except Exception as e:
                hash_results[algorithm] = "Error: " + str(e)
        return hash_results
    def clear_scroll_layout(self):
        for i in reversed(range(self.ui.verticalLayout_3.count())):
            widget = self.ui.verticalLayout_3.itemAt(i).widget()
            if widget is not None:
                widget.deleteLater()

    def hashcracker_crackhash(self):
        hashtype = self.ui.hashcraker_combobox.currentText()
        targethash = self.ui.hashcrackler_lineedit.text()

        #if the file is not selected
        if not self.hashcraker_selectedfile:
            QMessageBox.warning(self, "File Not Selected", "Please select a file containing passwords.")
            return
        class CrackThread(QThread):
            progress = pyqtSignal(int)
            result = pyqtSignal(str)
            finished = pyqtSignal()

            def __init__(self, hashtype, targethash, filename):
                super().__init__()
                self.hashtype = hashtype
                self.targethash = targethash
                self.filename = filename
                self.stopped = False

            def run(self):
                with open(self.filename, 'r') as f:
                    lines = f.readlines()
                    total_lines = len(lines)

                    for idx, line in enumerate(lines):
                        if self.stopped:
                            break

                        clean_word = line.strip()

                        # Hash the word based on the selected hash type
                        if self.hashtype == 'SHA 256':
                            m = hashlib.sha256(clean_word.encode()).hexdigest()
                        elif self.hashtype == 'MD5':
                            m = hashlib.md5(clean_word.encode()).hexdigest()
                        elif self.hashtype == 'SHA 512':
                            m = hashlib.sha512(clean_word.encode()).hexdigest()
                        elif self.hashtype == 'SHA 1':
                            m = hashlib.sha1(clean_word.encode()).hexdigest()

                        # Update progress bar
                        progress_value = int((idx + 1) / total_lines * 100)
                        self.progress.emit(progress_value)

                        # Check if the generated hash matches the target hash
                        if m.upper() == self.targethash.upper():
                            self.result.emit(f"Hash found: {clean_word}")
                            self.finished.emit()
                            return

                    self.result.emit("Hash not found in wordlist.")
                    self.finished.emit()

            def stop(self):
                self.stopped = True
        self.crack_thread = CrackThread(hashtype, targethash, self.hashcraker_selectedfile)
        self.crack_thread.progress.connect(self.hashcracker_update_progress)
        self.crack_thread.result.connect(self.hashcracker_handle_result)
        self.crack_thread.finished.connect(self.hashcracker_crack_finished)
        self.crack_thread.start()

        # Disable Crack Hash button and enable Stop button
        self.ui.hashcracker_crackfilepb.setEnabled(False)
        self.ui.hashcracker_stoppb.setEnabled(True)
        print("ok")

    def hashcracker_stop_cracking(self):
        # Signal the thread to stop
        self.crack_thread.stop()
        # Disable Stop button
        self.ui.hashcracker_stoppb.setEnabled(False)
    def hashcracker_update_progress(self, value):
        self.ui.hashcracker_progressbar.setValue(value)

    def hashcracker_handle_result(self, result):
        self.ui.hashcracker_resultlabel.setText(result)

    def hashcracker_crack_finished(self):
        # Re-enable Crack Hash button
        self.ui.hashcracker_crackfilepb.setEnabled(True)
        # Disable Stop button
        self.ui.hashcracker_stoppb.setEnabled(False)

    def hashcracker_selectfile(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Text files (*.txt)")
        if file_dialog.exec_():
            self.hashcraker_selectedfile = file_dialog.selectedFiles()[0]

    def when_hashcrackerserlction_pb_clicked(self):
        self.ui.contentviewstacked.setCurrentIndex(6)
        self.ui.resultviewstacke.setCurrentIndex(7)
        buttons = [self.ui.backtotreeviewpb, self.ui.stegnographyselectionpb, self.ui.datarecovryoption,self.ui.bruteforce_selectionpb,self.ui.malwareanalysis_slectionpb,self.ui.hashcrackerselection_pb,self.ui.hashcalcselction_pb]
        for button in buttons:
            if button is not self.ui.hashcrackerselection_pb:
                button.setChecked(False)
            else:
                button.setChecked(True)
    def when_malwarefilescan_clicked(self):

        self.ui.malware_filescanpb, _ = QFileDialog.getOpenFileName(self, "Select File to Scan")
        if self.ui.malware_filescanpb:
            self.ui.selected_direcory.setText(f"Selected File: {self.ui.malware_filescanpb}")
        if not self.ui.malware_filescanpb:
            self.ui.selected_direcory.setText("Please select a file to scan.")
            return

        self.ui.label_2.setText("Result: Scanning in progress...")
        print("ok")
        virus_info = self.malware_checker(self.ui.malware_filescanpb)
        self.ui.malware_progressbar.setValue(100)

        # Emit the result
        if virus_info:
            self.ui.label_2.setText(f"Result: Malware detected in {self.ui.malware_filescanpb}\nVirus Info: {virus_info}")
        else:
            self.ui.label_2.setText("Result: No malware found.")
    def malware_checker(self, path_of_file):
        hash_malware_check = self.sha256_hash(path_of_file)

        for i, virus_hash in enumerate(malware_hashes):
            if virus_hash == hash_malware_check:
                return virusinfo[i]

        return None

    def sha256_hash(self, filename):
        import hashlib
        try:
            with open(filename, "rb") as f:
                bytes = f.read()
                sha256hash = hashlib.sha256(bytes).hexdigest()

            return sha256hash
        except:
            return None

    def when_malware_cutomscanpbclicked(self):
        class ScannerThread(QThread):
            progress_update = pyqtSignal(int)
            file_update = pyqtSignal(str)
            scan_completed = pyqtSignal(str)

            def __init__(self, path):
                super().__init__()
                self.path = path
                self.stopped = False

            def run(self):
                global virusname
                virusname = []

                if os.path.isfile(self.path):
                    self.scan_file(self.path)
                elif os.path.isdir(self.path):
                    self.scan_directory(self.path)

                # Reset the stopped flag
                self.stopped = False

                # Emit signal indicating scan completion and result
                if virusname:
                    self.scan_completed.emit("Malware detected: {}".format(virusname))
                else:
                    self.scan_completed.emit("No malware found.")

            def stop_scan(self):
                self.stopped = True

            def scan_directory(self, directory):
                files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(directory) for f in filenames]
                total_files = len(files)
                scanned_files = 0

                for file in files:
                    if self.stopped:
                        break

                    self.file_update.emit(file)

                    if self.malware_checker(file) != 0:
                        virusname.append(file)
                        os.remove(file)

                    scanned_files += 1
                    progress_value = int((scanned_files / total_files) * 100)
                    self.progress_update.emit(progress_value)

            def scan_file(self, file):
                self.file_update.emit(file)

                if self.malware_checker(file) != 0:
                    virusname.append(file)
                    os.remove(file)

                progress_value = 100
                self.progress_update.emit(progress_value)

            def malware_checker(self, path_of_file):
                hash_malware_check = self.sha256_hash(path_of_file)
                counter = 0

                for i in malware_hashes:
                    if i == hash_malware_check:
                        return virusinfo[counter]
                    counter += 1

                return 0

            def sha256_hash(self, filename):
                import hashlib
                try:
                    with open(filename, "rb") as f:
                        bytes = f.read()
                        sha256hash = hashlib.sha256(bytes).hexdigest()

                    return sha256hash
                except:
                    return 0

        self.ui.malware_customscan_pb = QFileDialog.getExistingDirectory(self, "Select Directory")
        if self.ui.malware_customscan_pb:
            self.ui.selected_direcory.setText(f"Selected File: {self.ui.malware_customscan_pb}")

        if not self.ui.malware_customscan_pb:
            self.ui.selected_direcory.setText("Please select a file or directory to scan.")
            return
        self.ui.malwareanalysis_stopbtn.setEnabled(True)

        self.ui.label_2.setText("Result: Scanning in progress...")
        self.thread = ScannerThread(self.ui.malware_customscan_pb)
        self.thread.progress_update.connect(self.update_progress)
        self.thread.file_update.connect(self.update_current_file)
        self.thread.scan_completed.connect(self.scan_completed)
        self.thread.start()

    def update_progress(self, value):
        self.ui.malware_progressbar.setValue(value)
    def update_current_file(self, file):
        self.ui.curremtfile_labe.setText(f"Current File: {file}")
    def scan_completed(self, result):
        self.ui.label_2.setText(result)
        self.ui.malwareanalysis_stopbtn.setEnabled(False)

    def stop_scan(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop_scan()
            self.thread.wait()  # Wait for the thread to finish
            self.thread.deleteLater()  # Delete the thread
            self.thread = None  # Reset the thread instance
            self.ui.malwareanalysis_stopbtn.setEnabled(False)

            self.ui.label_2.setText("Scanning Stopped")

    def when_malwareanalysisselection_pbclicked(self):

        self.ui.resultviewstacke.setCurrentIndex(6)
        self.ui.contentviewstacked.setCurrentIndex(5)
        buttons = [self.ui.backtotreeviewpb, self.ui.stegnographyselectionpb, self.ui.datarecovryoption,self.ui.bruteforce_selectionpb,self.ui.malwareanalysis_slectionpb,self.ui.hashcrackerselection_pb,self.ui.hashcalcselction_pb]
        for button in buttons:
            if button is not self.ui.malwareanalysis_slectionpb:
                button.setChecked(False)
            else:
                button.setChecked(True)
    def add_word(self):
        word = self.ui.custompasswordinput_lineedit.text().strip()
        if word:
            self.words.append(word)
            self.ui.custompasswordinput_lineedit.clear()
    def when_custompassword_generatebtnCLicked(self):
        self.ui.resultviewstacke.setCurrentIndex(4)
        self.ui.contentviewstacked.setCurrentIndex(3)
        generated_passwords = resourcecode.generate_passwords(self.words)
        if isinstance(generated_passwords, str):
            # Show warning if there was an issue with password generation
            QMessageBox.warning(self, 'Warning', generated_passwords)
        else:
            # Prompt user for file location to save passwords
            file_dialog = QFileDialog()
            file_path, _ = file_dialog.getSaveFileName(self, "Save Passwords to File", "",
                                                       "Text Files (*.txt);;All Files (*)")

            if file_path:
                try:
                    with open(file_path, 'w') as file:
                        file.write('\n'.join(generated_passwords))
                except Exception as e:
                    # Show error if there was an issue saving the file
                    QMessageBox.critical(self, 'Error', f'An error occurred while saving the file: {str(e)}')

    def when_custompasspb_clicked(self):
        self.ui.contentviewstacked.setCurrentIndex(4)
        self.ui.resultviewstacke.setCurrentIndex(5)
    def when_bruteforce_attacked_clicked(self):
        self.stop_attack = False
        brute_force_thread = Thread(target=self.brute_force_attack)
        brute_force_thread.start()

    def brute_force_attack(self):
        n_words = len(list(open(self.wordlist, "rb")))
        for index, word in enumerate(tqdm(open(self.wordlist, "rb"), total=n_words, unit="word")):
            if self.stop_attack:
                break
            try:
                self.zip_file_object = zipfile.ZipFile(self.zip_file)
                self.zip_file_object.extractall(pwd=word.strip())
            except:
                continue
            else:
                result = f"Password found: {word.decode().strip()}"
                self.ui.bruteforce_resultlabel.setText(result)
                break
            finally:
                progress_value = int((index + 1) / n_words * 100)
                self.ui.bruteforeceprogressbar.setValue(progress_value)
        else:
            # This part will be executed if the loop completes without breaking
            self.ui.bruteforce_resultlabel.setText("Password not detected")

    def check_buttons_state(self):
        if self.zip_file:
            self.ui.brutefore_attackpb.setEnabled(True)
            self.ui.bruteforce_stoppb.setEnabled(True)
        else:
            self.ui.brutefore_attackpb.setEnabled(False)
            self.ui.bruteforce_stoppb.setEnabled(False)

    def when_bruteforce_stopclicked(self):
        self.stop_attack = True
        self.ui.bruteforce_resultlabel.clear()
        if self.zip_file_object:
            self.zip_file_object.close()
    def when_select_passwordlistpb_clicked(self):
        self.ui.bruteforce_resultlabel.clear()
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("Text Files (*.txt)")
        file_dialog.setOptions(options)
        self.wordlist, _ = file_dialog.getOpenFileName(self, "Select Wordlist File", "", "Text Files (*.txt)")
        self.check_buttons_state()
    def when_select_rarfilepb_clicked(self):
        self.ui.bruteforce_resultlabel.clear()
        self.check_buttons_state()
        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("Zip Files (*.zip *.rar)")
        file_dialog.setOptions(options)
        self.zip_file, _ = file_dialog.getOpenFileName(self, "Select Zip File", "", "Zip Files (*.zip *.rar)")
        self.check_buttons_state()
    def when_bruteforcepb_clicked(self):
        self.ui.bruteforce_resultlabel.clear()
        self.ui.resultviewstacke.setCurrentIndex(4)
        self.ui.contentviewstacked.setCurrentIndex(3)
        buttons = [self.ui.backtotreeviewpb, self.ui.stegnographyselectionpb, self.ui.datarecovryoption,self.ui.bruteforce_selectionpb,self.ui.malwareanalysis_slectionpb,self.ui.hashcrackerselection_pb,self.ui.hashcalcselction_pb]
        for button in buttons:
            if button is not self.ui.bruteforce_selectionpb:
                button.setChecked(False)
            else:
                button.setChecked(True)
    def when_slectlocationb_clicked(self):
        self.ui.bruteforce_resultlabel.clear()
        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
        self.output_directory=folder_path
        print(self.output_directory)
    def when_jpgrecovrypb_clicked(self):
        if not self.recovery_thread or not self.recovery_thread.isRunning():
            drive = "\\\\.\\C:"
            output_directory = self.output_directory
            class InnerRecoveryThread(QThread):

                finished_signal = pyqtSignal()

                def run(self):
                    print("ok")
                    fileD = open(drive, "rb")
                    size = 512

                    byte = fileD.read(size)
                    offs = 0
                    drec = False
                    rcvd = 0

                    while byte and not self.isInterruptionRequested():

                        found = byte.find(b'\xff\xd8\xff\xe0\x00\x10\x4a\x46')
                        if found >= 0:
                            drec = True

                            f='Found JPG at location: ' + str(hex(found + (size * offs))) + ' ===='

                            print_recoverdfiles(f)
                            file_path = os.path.join(output_directory,
                                                     f"{rcvd}.jpg")  # Specify the file path in the output directory
                            fileN = open(file_path, "wb")
                            fileN.write(byte[found:])

                            while drec:
                                byte = fileD.read(size)
                                bfind = byte.find(b'\xff\xd9')
                                if bfind >= 0:
                                    fileN.write(byte[:bfind + 2])
                                    fileD.seek((offs + 1) * size)
                                    drec = False
                                    rcvd += 1
                                    fileN.close()
                                else:
                                    fileN.write(byte)
                        byte = fileD.read(size)
                        offs += 1

                    fileD.close()
                    self.finished_signal.emit()

            self.recovery_thread = InnerRecoveryThread()

            self.recovery_thread.start()
        def print_recoverdfiles(f):
            self.ui.listWidget_2.addItem(f)

    def when_stoprecoveryclicked(self):
        if self.recovery_thread and self.recovery_thread.isRunning():
            self.recovery_thread.requestInterruption()
            self.ui.listWidget_2.clear()
        else:
            print("No recovery in progress.")




    def when_datarecoeryoption_clicked(self):
        self.ui.contentviewstacked.setCurrentIndex(2)
        self.ui.resultviewstacke.setCurrentIndex(3)
        buttons = [self.ui.backtotreeviewpb, self.ui.stegnographyselectionpb, self.ui.datarecovryoption,self.ui.bruteforce_selectionpb,self.ui.malwareanalysis_slectionpb,self.ui.hashcrackerselection_pb,self.ui.hashcalcselction_pb]
        for button in buttons:
            if button is not self.ui.datarecovryoption:
                button.setChecked(False)
            else:
                button.setChecked(True)
    def when_automatedstegscanclicked(self):
        self.ui.resultviewstacke.setCurrentIndex(2)
        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folder_path:
            png_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.lower().endswith('.png')]
            file_name=self.display_png_files(png_files)

    def display_png_files(self, png_files):
        for item in png_files:
            if item:
                if resourcecode.detect_steganography(item) == True:
                    self.ui.listWidget.addItem(f'{item}')


    def when_cuctomstegpb_clicked(self):
        self.ui.stegimagelabel.clear()
        self.ui.resultviewstacke.setCurrentIndex(0)
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, 'Select PNG File', '', 'PNG Files (*.png);;All Files (*)',
                                                   options=options)

        pixmap = QPixmap(file_name)
        if pixmap.isNull():
            print(f"Error loading image from path")
        else:
            scaled_pixmap = pixmap.scaledToWidth(self.ui.stegimagelabel.width(), Qt.SmoothTransformation)
            self.ui.stegimagelabel.setPixmap(scaled_pixmap)


        if resourcecode.detect_steganography(file_name)==True:
            self.ui.customstegresultlabel.setText("Steganography detected! LSB anomalies found.")
            self.png_info(file_name)

        else:
            self.ui.customstegresultlabel.setText("No steganography detected")


    def png_info(self,file_path):
        try:
            #to concatinate the text
            current_text = self.ui.customstegresultlabel.text()

            # Get file information
            file_info = os.stat(file_path)
            creation_time = file_info.st_ctime
            modification_time = file_info.st_mtime

            # Convert timestamps to human-readable format
            creation_date = str(datetime.datetime.fromtimestamp(creation_time))
            modification_date = str(datetime.datetime.fromtimestamp(modification_time))

            with Image.open(file_path) as img:
                width, height = img.size
                mode = img.mode
                new_text=(f"{current_text}\nWidth: {width}\nHeight: {height}\nColor Mode: {mode}\nCreation Date: {creation_date}\nModification Date: {modification_date}\nModification Date: {modification_date}\n")
                self.ui.customstegresultlabel.setText(new_text)

        except Exception as e:
            print(f"Error: {e}")



    def when_steg_mode_slected(self):

        self.ui.contentviewstacked.setCurrentIndex(1)
        self.ui.resultviewstacke.setCurrentIndex(0)
        buttons = [self.ui.backtotreeviewpb, self.ui.stegnographyselectionpb, self.ui.datarecovryoption,self.ui.bruteforce_selectionpb,self.ui.malwareanalysis_slectionpb,self.ui.hashcrackerselection_pb,self.ui.hashcalcselction_pb]
        for button in buttons:
            if button is not self.ui.stegnographyselectionpb:
                button.setChecked(False)
            else:
                button.setChecked(True)
    #to select and print the file infos
    #     self.ui.tree_view.selectionModel().selectionChanged.connect(self.show_file_info)
    # def show_file_info(self):
    #     selected_index = self.ui.tree_view.currentIndex()
    #     file_info = self.file_system_model.fileInfo(selected_index)
    #     # Display file info in the console (you can customize this part)
    #     print("File Name:", file_info.fileName())
    #     print("Size:", file_info.size(), "bytes")
    #     print("Modified Date:", file_info.lastModified().toString())
    #     print("Created Date:", file_info.created().toString())
    #     print("-" * 40)





if __name__ == '__main__':
    malware_hashes = list(open("Sha256\\virusHash.unibit", 'r').read().split('\n'))
    virusinfo = list(open("Sha256\\virusInfo.unibit", 'r').read().split('\n'))
    virusname = []
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec()


