import os
import gc
import sys
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from PyQt5.QtWidgets import *

from uiClass import Ui_MainWindow
from myClass import file_crypto


class guiSafeKeeper(QMainWindow, Ui_MainWindow):
	# Class Variable
	__InputFiles = []
	__Dir = []


	def __init__(self):
		super(guiSafeKeeper, self).__init__()
		self.ui = Ui_MainWindow()
		self.ui.setupUi(self)
		self.ui.pushButton.clicked.connect(self.__openFileNamesDialog)
		self.ui.pushButton_2.clicked.connect(self.__openDirNameDialog)
		self.ui.pushButton_4.clicked.connect(self.Start)


	def __openFileNamesDialog(self):
		dlg = QFileDialog()
		dlg.setFileMode(QFileDialog.ExistingFiles)
		if dlg.exec_():
			self.__InputFiles = dlg.selectedFiles()
			tmp = ""
			for i in self.__InputFiles:
				tmp += os.path.basename(i)
				tmp += "; "
			self.ui.lineEdit.setText(tmp)


	def __openDirNameDialog(self):
		dlg = QFileDialog()
		dlg.setFileMode(QFileDialog.Directory)
		if dlg.exec_():
			self.__Dir = dlg.selectedFiles()
			tmp = ""
			for i in self.__Dir:
				tmp += i
			self.ui.lineEdit_2.setText(tmp)
			

	def Start(self):
		self.ui.progressBar.setMaximum(len(self.__InputFiles))
		v = 0
		self.ui.progressBar.setValue(v)
		for i in self.__InputFiles:
			a = file_crypto()
			a.set_passwd(self.ui.lineEdit_3.text())
			if not a.check_password():
				QMessageBox.about(self, 'ERROR', "Invalid password")
				break
			if self.ui.comboBox.currentText() == "Encryption":
				if os.path.isfile(i) and os.path.isdir(self.__Dir[0]):
					a.set_fi(i)
					a.set_fo(os.path.join(self.__Dir[0], os.path.basename(i) + ".enc"))
					if self.ui.lineEdit_4.text():
						a.set_aad(self.ui.lineEdit_4.text())
					try:
						a.encrypt_file()
					except:
						QMessageBox.about(self, 'ERROR', "Unknow error")
					if self.ui.checkBox.isChecked():
						calc_hash = a.calculate_hash()
						self.ui.textEdit.insertPlainText("Plain data\r\n")
						self.ui.textEdit.insertPlainText(os.path.join(self.__Dir[0], os.path.basename(i) + ".enc")+"\r\n")
						self.ui.textEdit.insertPlainText(calc_hash[0]+"\r\n")
						self.ui.textEdit.insertPlainText("Encrypted data\r\n")
						self.ui.textEdit.insertPlainText(i+"\r\n")
						self.ui.textEdit.insertPlainText(calc_hash[1]+"\r\n")
					if self.ui.radioButton_3.isChecked():
						pass
					if self.ui.radioButton_2.isChecked():
						a.simple_delete()
					if self.ui.radioButton.isChecked():
						a.wipe_data()
						a.simple_delete()						
				else:
					QMessageBox.about(self, 'ERROR', "File or folder do not exist")
					continue
			else:
				if self.ui.comboBox.currentText() == "Decryption":
					if os.path.isfile(i) and os.path.isdir(self.__Dir[0]):
						a.set_fi(i)
						a.set_fo(os.path.join(self.__Dir[0], os.path.basename(i)[:-4]))
						if self.ui.lineEdit_4.text():
							a.set_aad(self.ui.lineEdit_4.text())
						try:
							a.decrypt_file()
						except:
							QMessageBox.about(self, 'ERROR', "Unknow error")
						if self.ui.checkBox.isChecked():
							calc_hash = a.calculate_hash()
							self.ui.textEdit.insertPlainText("Encrypted data\r\n")
							self.ui.textEdit.insertPlainText(i+"\r\n")
							self.ui.textEdit.insertPlainText(calc_hash[0]+"\r\n")
							self.ui.textEdit.insertPlainText("Plain data\r\n")
							self.ui.textEdit.insertPlainText(os.path.join(self.__Dir[0], os.path.basename(i)[:-4])+"\r\n")
							self.ui.textEdit.insertPlainText(calc_hash[1]+"\r\n")
						if self.ui.radioButton_3.isChecked():
							pass
						if self.ui.radioButton_2.isChecked():
							a.simple_delete()
						if self.ui.radioButton.isChecked():
							a.wipe_data()
							a.simple_delete()
					else:
						QMessageBox.about(self, 'ERROR', "File or folder do not exist")
						continue
			v += 1
			self.ui.progressBar.setValue(v)
		gc.collect()


if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = guiSafeKeeper()
	window.show()
	sys.exit(app.exec_())

