/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.autopsy.ingest;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.openide.util.Exceptions;
import org.sleuthkit.autopsy.coreutils.ModuleSettings;
import org.sleuthkit.autopsy.coreutils.PlatformUtil;

public class IngestProfileList {

    private static final String PROFILE_FOLDER = "profiles";
    private static final String PROFILE_NAME_KEY = "Profile_Name";
    private static final String PROFILE_DESC_KEY = "Profile_Description";
    private static final String PROFILE_SELECTED_KEY = "Profile_Selected";
    List<IngestProfile> profileList = null;
    List<String> nameList = null;
    private IngestProfile lastUsedProfile = null;

    List<IngestProfile> getIngestProfileList() {
        if (profileList == null) {
            loadProfileList();
        }
        return profileList;
    }

    void readFilesFromDirectory() {

        File dir = Paths.get(PlatformUtil.getUserConfigDirectory(), PROFILE_FOLDER).toFile();
        System.out.println(dir.toString());  //WJS-TODO remove sout
        File[] directoryListing = dir.listFiles();

        if (directoryListing != null) {
            profileList = new ArrayList<>();
            nameList = new ArrayList<>();
            for (File child : directoryListing) {
                String name = child.getName().split("\\.")[0];
                String context = PROFILE_FOLDER + File.separator + name;
                // name = ModuleSettings.getConfigSetting(context, PROFILE_NAME_KEY);
                System.out.println("-=-=-=-=-=-" + name);
                nameList.add(name);
                String desc = ModuleSettings.getConfigSetting(context, PROFILE_DESC_KEY);
                System.out.println(desc);
                String selected = ModuleSettings.getConfigSetting(context, PROFILE_SELECTED_KEY);
                profileList.add(new IngestProfile(name, desc, selected));
            }
        } else {
            profileList = Collections.emptyList();
        }
    }

    void loadProfileList() {
        readFilesFromDirectory();
        lastUsedProfile = new IngestProfile("lastProfileUsed", "last used description here soon", "lastProfileUsed");
        //WJS-TODO add saved profile list items to list;

    }

    IngestProfile getLastUsedProfile() {
        return lastUsedProfile;
    }

    void saveProfileList() {
        //save last used profile
        for (IngestProfile profile : getIngestProfileList()) {
            IngestProfile.saveProfile(profile);
        }
    }

    static class IngestProfile {

        static final String ENABLED_MODULES_KEY = "Enabled_Ingest_Modules"; //NON-NLS
        static final String DISABLED_MODULES_KEY = "Disabled_Ingest_Modules"; //NON-NLS
        private final String name;
        private final String description;
        private final String fileIngestFilter; //can this just be the name? //WJS-TODO replace with A list of selected/unselected ingest modules and runtime settings for the modules.

        IngestProfile(String name, String desc, String selected) {
            this.name = name;
            this.description = desc;
            this.fileIngestFilter = selected;
        }

        @Override
        public String toString() {
            return getName();
        }

        /**
         * @return the name
         */
        String getName() {
            return name;
        }

        /**
         * @return the description
         */
        String getDescription() {
            return description;
        }

        /**
         * @return the fileIngestFilter
         */
        String getFileIngestFilter() {
            return fileIngestFilter;
        }

        static void deleteProfile(IngestProfile selectedProfile) {
            try {
                Files.deleteIfExists(Paths.get(PlatformUtil.getUserConfigDirectory(), PROFILE_FOLDER, selectedProfile.getName() + ".properties"));
                Files.deleteIfExists(Paths.get(PlatformUtil.getUserConfigDirectory(), selectedProfile.getName() + ".properties"));
                FileUtils.deleteDirectory(IngestJobSettings.getSavedModuleSettingsFolder(selectedProfile.getName() + File.separator).toFile());
            } catch (IOException ex) {
                Exceptions.printStackTrace(ex);
            }

        }

        static void renameProfile(String oldName, String newName) {
            if (!oldName.equals(newName)) { //if renameProfile was called with the new name being the same as the old name, it is complete already
                File oldFile = Paths.get(PlatformUtil.getUserConfigDirectory(), PROFILE_FOLDER, oldName + ".properties").toFile();
                File newFile = Paths.get(PlatformUtil.getUserConfigDirectory(), PROFILE_FOLDER, newName + ".properties").toFile();
                oldFile.renameTo(newFile);
                oldFile = Paths.get(PlatformUtil.getUserConfigDirectory(), oldName + ".properties").toFile();
                newFile = Paths.get(PlatformUtil.getUserConfigDirectory(), newName + ".properties").toFile();
                oldFile.renameTo(newFile);
                oldFile = IngestJobSettings.getSavedModuleSettingsFolder(oldName + File.separator).toFile();
                newFile = IngestJobSettings.getSavedModuleSettingsFolder(newName + File.separator).toFile();
                oldFile.renameTo(newFile);
            }

        }

        HashSet<String> getModuleNames(String key) {
            if (ModuleSettings.settingExists(this.getName(), key) == false) {
                ModuleSettings.setConfigSetting(this.getName(), key, "");
            }
            HashSet<String> moduleNames = new HashSet<>();
            String modulesSetting = ModuleSettings.getConfigSetting(this.getName(), key);
            if (!modulesSetting.isEmpty()) {
                String[] settingNames = modulesSetting.split(", ");
                for (String name : settingNames) {
                    // Map some old core module names to the current core module names.
                    switch (name) {
                        case "Thunderbird Parser": //NON-NLS
                        case "MBox Parser": //NON-NLS
                            moduleNames.add("Email Parser"); //NON-NLS
                            break;
                        case "File Extension Mismatch Detection": //NON-NLS
                            moduleNames.add("Extension Mismatch Detector"); //NON-NLS
                            break;
                        case "EWF Verify": //NON-NLS
                        case "E01 Verify": //NON-NLS
                            moduleNames.add("E01 Verifier"); //NON-NLS
                            break;
                        case "Archive Extractor": //NON-NLS
                            moduleNames.add("Embedded File Extractor"); //NON-NLS
                            break;
                        default:
                            moduleNames.add(name);
                    }
                }
            }
            return moduleNames;
        }

//        FilesSet getFileIngestFilter() {
//            if (ModuleSettings.settingExists(this.name, key) == false) {
//                ModuleSettings.setConfigSetting(this.name, key, "");
//            }
//            HashSet<String> moduleNames = new HashSet<>();
//            String modulesSetting = ModuleSettings.getConfigSetting(this.name, key);
//
//        }
        static void saveProfile(IngestProfile profile) {
            System.out.println("==============PNAME===========" + profile.getName());
            String context = PROFILE_FOLDER + File.separator + profile.getName();

            ModuleSettings.setConfigSetting(context, PROFILE_NAME_KEY, profile.getName());//WJS-TODO write name, desc, context
            ModuleSettings.setConfigSetting(context, PROFILE_DESC_KEY, profile.getDescription());//WJS-TODO write name, desc, context
            ModuleSettings.setConfigSetting(context, PROFILE_SELECTED_KEY, profile.getFileIngestFilter());//WJS-TODO write name, desc, context
        }
    }

}
