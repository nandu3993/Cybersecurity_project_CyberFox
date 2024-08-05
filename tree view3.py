import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTreeView, QFileSystemModel, QVBoxLayout, QWidget, QHeaderView


class FileManager(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("File Manager")
        self.setGeometry(100, 100, 800, 600)

        self.init_ui()

    def init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        self.layout = QVBoxLayout(self.central_widget)

        # Create a file system model
        self.file_system_model = QFileSystemModel()
        self.file_system_model.setRootPath("")

        # Set name filters to display only files (no directories)
        self.file_system_model.setNameFilters(["*"])
        self.file_system_model.setNameFilterDisables(False)

        # Create a tree view for file navigation
        self.tree_view = QTreeView()
        self.tree_view.setModel(self.file_system_model)
        self.tree_view.setRootIndex(self.file_system_model.index(""))
        self.tree_view.setColumnWidth(0, 250)
        self.tree_view.setHeaderHidden(False)

        # Set custom header labels
        header = self.tree_view.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        header.setSectionsClickable(True)

        # Add components to the layout
        self.layout.addWidget(self.tree_view)

        # Connect selection change event to display file info
        self.tree_view.selectionModel().selectionChanged.connect(self.show_file_info)

    def show_file_info(self):
        selected_index = self.tree_view.currentIndex()
        file_info = self.file_system_model.fileInfo(selected_index)

        # Display file info in the console (you can customize this part)
        print("File Name:", file_info.fileName())
        print("Size:", file_info.size(), "bytes")
        print("Modified Date:", file_info.lastModified().toString())
        print("Created Date:", file_info.created().toString())
        print("-" * 40)


def main():
    app = QApplication(sys.argv)
    file_manager = FileManager()
    file_manager.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
