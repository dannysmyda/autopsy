/*
 * Autopsy Forensic Browser
 *
 * Copyright 2018 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.autopsy.contentviewers;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Cursor;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.logging.Level;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.apache.commons.io.FilenameUtils;
import org.openide.util.NbBundle;
import org.openide.windows.WindowManager;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.casemodule.services.Services;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.coreutils.TimeStampUtils;

/**
 * A file content viewer for SQLite database files.
 */
class SQLiteViewer extends javax.swing.JPanel implements FileTypeViewer {

    private static final long serialVersionUID = 1L;
    public static final String[] SUPPORTED_MIMETYPES = new String[]{"application/x-sqlite3"};
    private static final int ROWS_PER_PAGE = 100;
    private static final Logger logger = Logger.getLogger(FileViewer.class.getName());
    private final SQLiteTableView selectedTableView = new SQLiteTableView();
    private AbstractFile sqliteDbFile;
    private File tmpDbFile;
    private Connection connection;
    private int numRows;    // num of rows in the selected table
    private int currPage = 0; // curr page of rows being displayed

    /**
     * Constructs a file content viewer for SQLite database files.
     */
    public SQLiteViewer() {
        initComponents();
        jTableDataPanel.add(selectedTableView, BorderLayout.CENTER);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jHdrPanel = new javax.swing.JPanel();
        tablesDropdownList = new javax.swing.JComboBox<>();
        jLabel1 = new javax.swing.JLabel();
        numEntriesField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        currPageLabel = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        numPagesLabel = new javax.swing.JLabel();
        prevPageButton = new javax.swing.JButton();
        nextPageButton = new javax.swing.JButton();
        exportCsvButton = new javax.swing.JButton();
        jTableDataPanel = new javax.swing.JPanel();

        jHdrPanel.setPreferredSize(new java.awt.Dimension(536, 40));

        tablesDropdownList.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Item 1", "Item 2", "Item 3", "Item 4" }));
        tablesDropdownList.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tablesDropdownListActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(jLabel1, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.jLabel1.text")); // NOI18N

        numEntriesField.setEditable(false);
        numEntriesField.setText(org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.numEntriesField.text")); // NOI18N
        numEntriesField.setBorder(null);

        org.openide.awt.Mnemonics.setLocalizedText(jLabel2, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.jLabel2.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(currPageLabel, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.currPageLabel.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(jLabel3, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.jLabel3.text")); // NOI18N

        org.openide.awt.Mnemonics.setLocalizedText(numPagesLabel, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.numPagesLabel.text")); // NOI18N

        prevPageButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_back.png"))); // NOI18N
        org.openide.awt.Mnemonics.setLocalizedText(prevPageButton, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.prevPageButton.text")); // NOI18N
        prevPageButton.setBorderPainted(false);
        prevPageButton.setContentAreaFilled(false);
        prevPageButton.setDisabledSelectedIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_back_disabled.png"))); // NOI18N
        prevPageButton.setMargin(new java.awt.Insets(2, 0, 2, 0));
        prevPageButton.setPreferredSize(new java.awt.Dimension(23, 23));
        prevPageButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                prevPageButtonActionPerformed(evt);
            }
        });

        nextPageButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_forward.png"))); // NOI18N
        org.openide.awt.Mnemonics.setLocalizedText(nextPageButton, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.nextPageButton.text")); // NOI18N
        nextPageButton.setBorderPainted(false);
        nextPageButton.setContentAreaFilled(false);
        nextPageButton.setDisabledSelectedIcon(new javax.swing.ImageIcon(getClass().getResource("/org/sleuthkit/autopsy/corecomponents/btn_step_forward_disabled.png"))); // NOI18N
        nextPageButton.setMargin(new java.awt.Insets(2, 0, 2, 0));
        nextPageButton.setPreferredSize(new java.awt.Dimension(23, 23));
        nextPageButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                nextPageButtonActionPerformed(evt);
            }
        });

        org.openide.awt.Mnemonics.setLocalizedText(exportCsvButton, org.openide.util.NbBundle.getMessage(SQLiteViewer.class, "SQLiteViewer.exportCsvButton.text")); // NOI18N
        exportCsvButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exportCsvButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jHdrPanelLayout = new javax.swing.GroupLayout(jHdrPanel);
        jHdrPanel.setLayout(jHdrPanelLayout);
        jHdrPanelLayout.setHorizontalGroup(
            jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jHdrPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(tablesDropdownList, javax.swing.GroupLayout.PREFERRED_SIZE, 130, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(numEntriesField, javax.swing.GroupLayout.PREFERRED_SIZE, 71, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(15, 15, 15)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(currPageLabel)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(numPagesLabel)
                .addGap(18, 18, 18)
                .addComponent(prevPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, 0)
                .addComponent(nextPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(29, 29, 29)
                .addComponent(exportCsvButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jHdrPanelLayout.setVerticalGroup(
            jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jHdrPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(exportCsvButton)
                    .addComponent(nextPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(prevPageButton, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(jHdrPanelLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(tablesDropdownList, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel1)
                        .addComponent(numEntriesField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addComponent(jLabel2)
                        .addComponent(currPageLabel)
                        .addComponent(jLabel3)
                        .addComponent(numPagesLabel)))
                .addContainerGap())
        );

        jTableDataPanel.setLayout(new java.awt.BorderLayout());

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jHdrPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 569, Short.MAX_VALUE)
            .addComponent(jTableDataPanel, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jHdrPanel, javax.swing.GroupLayout.PREFERRED_SIZE, 53, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, 0)
                .addComponent(jTableDataPanel, javax.swing.GroupLayout.DEFAULT_SIZE, 317, Short.MAX_VALUE))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void nextPageButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_nextPageButtonActionPerformed
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        currPage++;
        if (currPage * ROWS_PER_PAGE > numRows) {
            nextPageButton.setEnabled(false);
        }
        currPageLabel.setText(Integer.toString(currPage));
        prevPageButton.setEnabled(true);

        // read and display a page of rows
        String tableName = (String) this.tablesDropdownList.getSelectedItem();
        readTable(tableName, (currPage - 1) * ROWS_PER_PAGE + 1, ROWS_PER_PAGE);
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }//GEN-LAST:event_nextPageButtonActionPerformed

    private void prevPageButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_prevPageButtonActionPerformed

        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        currPage--;
        if (currPage == 1) {
            prevPageButton.setEnabled(false);
        }
        currPageLabel.setText(Integer.toString(currPage));
        nextPageButton.setEnabled(true);

        // read and display a page of rows
        String tableName = (String) this.tablesDropdownList.getSelectedItem();
        readTable(tableName, (currPage - 1) * ROWS_PER_PAGE + 1, ROWS_PER_PAGE);
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }//GEN-LAST:event_prevPageButtonActionPerformed

    private void tablesDropdownListActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tablesDropdownListActionPerformed
        JComboBox<?> cb = (JComboBox<?>) evt.getSource();
        String tableName = (String) cb.getSelectedItem();
        if (null == tableName) {
            return;
        }
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        selectTable(tableName);
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }//GEN-LAST:event_tablesDropdownListActionPerformed

    /**
     * The action when the Export Csv button is pressed. The file chooser window will pop
     * up to choose where the user wants to save the csv file. The default location is case export directory.
     *
     * @param evt the action event
     */

    @NbBundle.Messages({"SQLiteViewer.csvExport.fileName.empty=Please input a file name for exporting.",
                        "SQLiteViewer.csvExport.title=Export to csv file"})
    private void exportCsvButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_exportCsvButtonActionPerformed
        Case openCase = Case.getCurrentCase();
        File caseDirectory = new File(openCase.getExportDirectory());        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDragEnabled(false);
        fileChooser.setCurrentDirectory(caseDirectory);
        //Set a filter to let the filechooser only work for csv files
        FileNameExtensionFilter csvFilter = new FileNameExtensionFilter("*.csv", "csv");
        fileChooser.addChoosableFileFilter(csvFilter);
        fileChooser.setAcceptAllFileFilterUsed(false);
        fileChooser.setFileFilter(csvFilter);
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        int choice = fileChooser.showDialog((Component) evt.getSource(), "File"); //TODO
        if (JFileChooser.APPROVE_OPTION == choice) {
            File file = fileChooser.getSelectedFile();
            if (file == null) {
                JOptionPane.showMessageDialog(this,
                        Bundle.SQLiteViewer_csvExport_fileName_empty(),
                        Bundle.SQLiteViewer_csvExport_title(), 
                        JOptionPane.WARNING_MESSAGE);
                return;
            } 
         
            exportTableToCsv(file);
        }
    }//GEN-LAST:event_exportCsvButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel currPageLabel;
    private javax.swing.JButton exportCsvButton;
    private javax.swing.JPanel jHdrPanel;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JPanel jTableDataPanel;
    private javax.swing.JButton nextPageButton;
    private javax.swing.JTextField numEntriesField;
    private javax.swing.JLabel numPagesLabel;
    private javax.swing.JButton prevPageButton;
    private javax.swing.JComboBox<String> tablesDropdownList;
    // End of variables declaration//GEN-END:variables

    @Override
    public List<String> getSupportedMIMETypes() {
        return Arrays.asList(SUPPORTED_MIMETYPES);
    }

    @Override
    public void setFile(AbstractFile file) {
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        sqliteDbFile = file;
        processSQLiteFile();
        WindowManager.getDefault().getMainWindow().setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
    }

    @Override
    public Component getComponent() {
        return this;
    }

    @Override
    public void resetComponent() {
        tablesDropdownList.setEnabled(true);
        tablesDropdownList.removeAllItems();
        numEntriesField.setText("");

        // close DB connection to file
        if (null != connection) {
            try {
                connection.close();
                connection = null;
            } catch (SQLException ex) {
                logger.log(Level.SEVERE, "Failed to close DB connection to file.", ex); //NON-NLS
            }
        }
        
        sqliteDbFile = null;
    }

    /**
     * Process the given SQLite DB file.
     */
    @NbBundle.Messages({
        "SQLiteViewer.comboBox.noTableEntry=No tables found",
        "SQLiteViewer.errorMessage.interrupted=The processing of the file was interrupted.",
        "SQLiteViewer.errorMessage.noCurrentCase=The case has been closed.",
        "SQLiteViewer.errorMessage.failedToExtractFile=The file could not be extracted from the data source.",
        "SQLiteViewer.errorMessage.failedToQueryDatabase=The database tables in the file could not be read.",
        "SQLiteViewer.errorMessage.failedToinitJDBCDriver=The JDBC driver for SQLite could not be loaded.",
        "# {0} - exception message", "SQLiteViewer.errorMessage.unexpectedError=An unexpected error occurred:\n{0).",})
    private void processSQLiteFile() {
                
        tablesDropdownList.removeAllItems();

        // Copy the file to temp folder
        String tmpDBPathName;
        try {
            tmpDBPathName = Case.getCurrentCaseThrows().getTempDirectory() + File.separator + sqliteDbFile.getName();
        } catch (NoCurrentCaseException ex) {
            logger.log(Level.SEVERE, "Current case has been closed", ex); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_errorMessage_noCurrentCase());
            return;
        }

        tmpDbFile = new File(tmpDBPathName);
        if (! tmpDbFile.exists()) {
            try {
                ContentUtils.writeToFile(sqliteDbFile, tmpDbFile);

                // Look for any meta files associated with this DB - WAL, SHM, etc. 
                findAndCopySQLiteMetaFile(sqliteDbFile, sqliteDbFile.getName() + "-wal");
                findAndCopySQLiteMetaFile(sqliteDbFile, sqliteDbFile.getName() + "-shm");
            } catch (IOException | NoCurrentCaseException | TskCoreException ex) {
                logger.log(Level.SEVERE, String.format("Failed to create temp copy of DB file '%s' (objId=%d)", sqliteDbFile.getName(), sqliteDbFile.getId()), ex); //NON-NLS
                MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_errorMessage_failedToExtractFile());
                return;
            }
        }
                
        try {
            // Load the SQLite JDBC driver, if necessary.
            Class.forName("org.sqlite.JDBC"); //NON-NLS  
            connection = DriverManager.getConnection("jdbc:sqlite:" + tmpDBPathName); //NON-NLS

            Map<String, String> dbTablesMap = getTables();
            if (dbTablesMap.isEmpty()) {
                tablesDropdownList.addItem(Bundle.SQLiteViewer_comboBox_noTableEntry());
                tablesDropdownList.setEnabled(false);
            } else {
                dbTablesMap.keySet().forEach((tableName) -> {
                    tablesDropdownList.addItem(tableName);
                });
            }
        } catch (ClassNotFoundException ex) {
            logger.log(Level.SEVERE, String.format("Failed to initialize JDBC SQLite '%s' (objId=%d)", sqliteDbFile.getName(), sqliteDbFile.getId()), ex); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_errorMessage_failedToinitJDBCDriver());
        } catch (SQLException ex) {
            logger.log(Level.SEVERE, String.format("Failed to get tables from DB file  '%s' (objId=%d)", sqliteDbFile.getName(), sqliteDbFile.getId()), ex); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_errorMessage_failedToQueryDatabase());
        }
    }

    /**
     * Searches for a meta file associated with the give SQLite db If found,
     * copies the file to the temp folder
     *
     * @param sqliteFile   - SQLIte db file being processed
     * @param metaFileName name of meta file to look for
     */
    private void findAndCopySQLiteMetaFile(AbstractFile sqliteFile, String metaFileName) throws NoCurrentCaseException, TskCoreException, IOException {
        Case openCase = Case.getCurrentCaseThrows();
        SleuthkitCase sleuthkitCase = openCase.getSleuthkitCase();
        Services services = new Services(sleuthkitCase);
        FileManager fileManager = services.getFileManager();
        List<AbstractFile> metaFiles = fileManager.findFiles(sqliteFile.getDataSource(), metaFileName, sqliteFile.getParent().getName());
        if (metaFiles != null) {
            for (AbstractFile metaFile : metaFiles) {
                String tmpMetafilePathName = openCase.getTempDirectory() + File.separator + metaFile.getName();
                File tmpMetafile = new File(tmpMetafilePathName);
                ContentUtils.writeToFile(metaFile, tmpMetafile);
            }
        }
    }

    /**
     * Gets the table names and schemas from the SQLite database file.
     *
     * @return A mapping of table names to SQL CREATE TABLE statements.
     */
    private Map<String, String> getTables() throws SQLException {
        Map<String, String> dbTablesMap = new TreeMap<>();
        Statement statement = null;
        ResultSet resultSet = null;
        try {
            statement = connection.createStatement();
            resultSet = statement.executeQuery(
                    "SELECT name, sql FROM sqlite_master "
                    + " WHERE type= 'table' "
                    + " ORDER BY name;"); //NON-NLS
            while (resultSet.next()) {
                String tableName = resultSet.getString("name"); //NON-NLS
                String tableSQL = resultSet.getString("sql"); //NON-NLS
                dbTablesMap.put(tableName, tableSQL);
            }
        } finally {
            if (null != resultSet) {
                resultSet.close();
            }
            if (null != statement) {
                statement.close();
            }
        }
        return dbTablesMap;
    }

    @NbBundle.Messages({"# {0} - tableName",
        "SQLiteViewer.selectTable.errorText=Error getting row count for table: {0}"
    })
    private void selectTable(String tableName) {

        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(
                    "SELECT count (*) as count FROM " + tableName)) { //NON-NLS{

            numRows = resultSet.getInt("count");
            numEntriesField.setText(numRows + " entries");

            currPage = 1;
            currPageLabel.setText(Integer.toString(currPage));
            numPagesLabel.setText(Integer.toString((numRows / ROWS_PER_PAGE) + 1));

            prevPageButton.setEnabled(false);

            if (numRows > 0) {
                nextPageButton.setEnabled(((numRows > ROWS_PER_PAGE)));
                readTable(tableName, (currPage - 1) * ROWS_PER_PAGE + 1, ROWS_PER_PAGE);
            } else {
                nextPageButton.setEnabled(false);
                selectedTableView.setupTable(Collections.emptyList());
            }
            
        } catch (SQLException ex) {
            logger.log(Level.SEVERE, String.format("Failed to load table %s from DB file '%s' (objId=%d)", tableName, sqliteDbFile.getName(), sqliteDbFile.getId()), ex); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_selectTable_errorText(tableName));
        }
    }

    @NbBundle.Messages({"# {0} - tableName",
        "SQLiteViewer.readTable.errorText=Error getting rows for table: {0}"})
    private void readTable(String tableName, int startRow, int numRowsToRead) {

        try (
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(
                    "SELECT * FROM " + tableName
                    + " LIMIT " + Integer.toString(numRowsToRead)
                    + " OFFSET " + Integer.toString(startRow - 1))) {

            ArrayList<Map<String, Object>> rows = resultSetToArrayList(resultSet);
            if (Objects.nonNull(rows)) {
                selectedTableView.setupTable(rows);
            } else {
                selectedTableView.setupTable(Collections.emptyList());
            }
        } catch (SQLException ex) {
            logger.log(Level.SEVERE, String.format("Failed to read table %s from DB file '%s' (objId=%d)", tableName, sqliteDbFile.getName(), sqliteDbFile.getId()), ex); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_readTable_errorText(tableName));
        }
    }

    @NbBundle.Messages("SQLiteViewer.BlobNotShown.message=BLOB Data not shown")
    private ArrayList<Map<String, Object>> resultSetToArrayList(ResultSet rs) throws SQLException {
        ResultSetMetaData metaData = rs.getMetaData();
        int columns = metaData.getColumnCount();
        ArrayList<Map<String, Object>> rowlist = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> row = new LinkedHashMap<>(columns);
            for (int i = 1; i <= columns; ++i) {
                if (rs.getObject(i) == null) {
                    row.put(metaData.getColumnName(i), "");
                } else {
                    if (metaData.getColumnTypeName(i).compareToIgnoreCase("blob") == 0) {
                        row.put(metaData.getColumnName(i), Bundle.SQLiteViewer_BlobNotShown_message());
                    } else {
                        row.put(metaData.getColumnName(i), rs.getObject(i));
                    }
                }
            }
            rowlist.add(row);
        }

        return rowlist;
    }
    
    @NbBundle.Messages({"SQLiteViewer.exportTableToCsv.write.errText=Failed to export table content to csv file.",
                        "SQLiteViewer.exportTableToCsv.emptyTable=Table is empty.",
                        "SQLiteViewer.exportTableToCsv.FileName=File name: ",
                        "SQLiteViewer.exportTableToCsv.TableName=Table name: "
    })
    private void exportTableToCsv(File file) {
        String tableName = (String) this.tablesDropdownList.getSelectedItem();
        String csvFileSuffix = "_" + tableName + "_" + TimeStampUtils.createTimeStamp() + ".csv";
        try (
                Statement statement = connection.createStatement();
                ResultSet resultSet = statement.executeQuery("SELECT * FROM " + tableName)) {
            List<Map<String, Object>> currentTableRows = resultSetToArrayList(resultSet);

            if (Objects.isNull(currentTableRows) || currentTableRows.isEmpty()) {
                logger.log(Level.INFO, String.format("The table %s is empty. (objId=%d)", tableName, sqliteDbFile.getId())); //NON-NLS
                MessageNotifyUtil.Message.info(Bundle.SQLiteViewer_exportTableToCsv_emptyTable());
            } else {
                String fileName = file.getName();
                File csvFile;
                if (FilenameUtils.getExtension(fileName).equalsIgnoreCase("csv")) {
                    csvFile = new File(file.getParentFile(), FilenameUtils.removeExtension(fileName) + csvFileSuffix);                    
                } else {
                    csvFile = new File(file.toString() + csvFileSuffix);
                }
                FileOutputStream out = new FileOutputStream(csvFile, false);

                out.write((Bundle.SQLiteViewer_exportTableToCsv_FileName() + fileName + "\n").getBytes());
                out.write((Bundle.SQLiteViewer_exportTableToCsv_TableName() + tableName + "\n").getBytes());
                // Set up the column names
                Map<String, Object> row = currentTableRows.get(0);
                StringBuffer header = new StringBuffer();
                for (Map.Entry<String, Object> col : row.entrySet()) {
                    String colName = col.getKey();
                    if (header.length() > 0) {
                        header.append(',').append(colName);
                    } else {
                        header.append(colName);
                    }
                }
                out.write(header.append('\n').toString().getBytes());

                for (Map<String, Object> maps : currentTableRows) {
                    StringBuffer valueLine = new StringBuffer();
                    maps.values().forEach((value) -> {
                        if (valueLine.length() > 0) {
                            valueLine.append(',').append(value.toString());
                        } else {
                            valueLine.append(value.toString());
                        }
                    });
                    out.write(valueLine.append('\n').toString().getBytes());
                }
            }
        } catch (SQLException ex) {
            logger.log(Level.SEVERE, String.format("Failed to read table %s from DB file '%s' (objId=%d)", tableName, sqliteDbFile.getName(), sqliteDbFile.getId()), ex); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_readTable_errorText(tableName));
        } catch (IOException ex) {
            logger.log(Level.SEVERE, String.format("Failed to export table %s to file '%s'", tableName, file.getName()), ex); //NON-NLS
            MessageNotifyUtil.Message.error(Bundle.SQLiteViewer_exportTableToCsv_write_errText());
        }
    }

    
}
