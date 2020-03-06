/*
 * Autopsy Forensic Browser
 *
 * Copyright 2019 Basis Technology Corp.
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
package org.sleuthkit.autopsy.thunderbirdparser;

import ezvcard.Ezvcard;
import ezvcard.VCard;
import ezvcard.parameter.EmailType;
import ezvcard.parameter.TelephoneType;
import ezvcard.property.Email;
import ezvcard.property.Organization;
import ezvcard.property.Photo;
import ezvcard.property.Telephone;
import ezvcard.property.Url;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import org.apache.commons.lang3.StringUtils;
import org.openide.util.NbBundle;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.casemodule.services.FileManager;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.MessageNotifyUtil;
import org.sleuthkit.autopsy.ingest.IngestJobContext;
import org.sleuthkit.autopsy.ingest.IngestServices;
import org.sleuthkit.autopsy.ingest.ModuleContentEvent;
import static org.sleuthkit.autopsy.thunderbirdparser.ThunderbirdMboxFileIngestModule.getRelModuleOutputPath;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.TskDataException;
import org.sleuthkit.datamodel.TskException;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper;

/**
 * A parser that can extract information from a vCard file and create the
 * appropriate artifacts.
 */
final class VcardParser {
    private static final String VCARD_HEADER = "BEGIN:VCARD";
    private static final long MIN_FILE_SIZE = 22;
    
    private static final String PHOTO_TYPE_BMP = "bmp";
    private static final String PHOTO_TYPE_GIF = "gif";
    private static final String PHOTO_TYPE_JPEG = "jpeg";
    private static final String PHOTO_TYPE_PNG = "png";
    private static final Map<String, String> photoTypeExtensions;
    static {
        photoTypeExtensions = new HashMap<>();
        photoTypeExtensions.put(PHOTO_TYPE_BMP, ".bmp");
        photoTypeExtensions.put(PHOTO_TYPE_GIF, ".gif");
        photoTypeExtensions.put(PHOTO_TYPE_JPEG, ".jpg");
        photoTypeExtensions.put(PHOTO_TYPE_PNG, ".png");
    }
    
    private static final Logger logger = Logger.getLogger(VcardParser.class.getName());
    
    private final IngestServices services = IngestServices.getInstance();
    private final FileManager fileManager;
    private final IngestJobContext context;
    private final Blackboard blackboard;
    private final SleuthkitCase tskCase;
    
    /**
     * Create a VcardParser object.
     */
    VcardParser(Case currentCase, IngestJobContext context) {
        this.context = context;
        tskCase = currentCase.getSleuthkitCase();
        blackboard = tskCase.getBlackboard();
        fileManager = currentCase.getServices().getFileManager();
    }

    /**
     * Is the supplied content a vCard file?
     * 
     * @param content The content to check.
     * 
     * @return True if the supplied content is a vCard file; otherwise false.
     */
    static boolean isVcardFile(Content content) {
        try {
            if (content.getSize() > MIN_FILE_SIZE) {
                byte[] buffer = new byte[VCARD_HEADER.length()];
                int byteRead = content.read(buffer, 0, VCARD_HEADER.length());
                if (byteRead > 0) {
                    String header = new String(buffer);
                    return header.equalsIgnoreCase(VCARD_HEADER);
                }
            }
        } catch (TskException ex) {
            logger.log(Level.WARNING, String.format("Exception while detecting if the file '%s' (id=%d) is a vCard file.",
                    content.getName(), content.getId())); //NON-NLS
        }
        
        return false;
    }
    
    /**
     * Parse the VCard file and compile its data in a VCard object. The
     * corresponding artifacts will be created.
     * 
     * @param vcardFile    The VCard file to be parsed.
     * @param abstractFile The abstract file with which to associate artifacts.
     * 
     * @throws IOException            If there is an issue parsing the VCard
     *                                file.
     * @throws NoCurrentCaseException If there is no open case.
     */
    void parse(AbstractFile abstractFile) throws IOException, NoCurrentCaseException, TskCoreException, Blackboard.BlackboardException {
        CommunicationArtifactsHelper helper = new CommunicationArtifactsHelper(tskCase, 
                EmailParserModuleFactory.getModuleName(), abstractFile, Account.Type.DEVICE);
        
        for (VCard vcard: Ezvcard.parse(new ReadContentInputStream(abstractFile)).all()) {
            addContactArtifact(vcard, abstractFile, helper);
        }
    }
    
    
    
    /**
     * Add a blackboard artifact for the given contact.
     *
     * @param vcard        The VCard that contains the contact information.
     * @param abstractFile The file associated with the data.
     * 
     * @throws NoCurrentCaseException if there is no open case.
     * 
     * @return The generated contact artifact.
     */
    @NbBundle.Messages({"VcardParser.addContactArtifact.indexError=Failed to index the contact artifact for keyword search."})
    private BlackboardArtifact addContactArtifact(VCard vcard, AbstractFile abstractFile, CommunicationArtifactsHelper helper) throws NoCurrentCaseException, TskCoreException, Blackboard.BlackboardException {
        List<BlackboardAttribute> attributes = new ArrayList<>();
       
        String name = "";
        if (vcard.getFormattedName() != null) {
            name = vcard.getFormattedName().getValue();
        } else {
            if (vcard.getStructuredName() != null) {
                // Attempt to put the name together if there was no formatted version
                for (String prefix:vcard.getStructuredName().getPrefixes()) {
                    name += prefix + " ";
                }
                if (vcard.getStructuredName().getGiven() != null) {
                    name += vcard.getStructuredName().getGiven() + " ";
                }
                if (vcard.getStructuredName().getFamily() != null) {
                    name += vcard.getStructuredName().getFamily() + " ";
                }
                for (String suffix:vcard.getStructuredName().getSuffixes()) {
                    name += suffix + " ";
                }
                if (! vcard.getStructuredName().getAdditionalNames().isEmpty()) {
                    name += "(";
                    for (String addName:vcard.getStructuredName().getAdditionalNames()) {
                        name += addName + " ";
                    }
                    name += ")";
                }
            }
        }
        ThunderbirdMboxFileIngestModule.addArtifactAttribute(name, BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, attributes);
        
        boolean hasAtleastOnePhoneOrEmailAttribute = false;
        for (Telephone telephone : vcard.getTelephoneNumbers()) {
            hasAtleastOnePhoneOrEmailAttribute |= addPhoneAttributes(telephone, abstractFile, attributes);
        }
        
        for (Email email : vcard.getEmails()) {
            hasAtleastOnePhoneOrEmailAttribute |= addEmailAttributes(email, abstractFile, attributes);
        }
        
        for (Url url : vcard.getUrls()) {
            ThunderbirdMboxFileIngestModule.addArtifactAttribute(url.getValue(), BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL, attributes);
        }
        
        for (Organization organization : vcard.getOrganizations()) {
            List<String> values = organization.getValues();
            if (values.isEmpty() == false) {
                ThunderbirdMboxFileIngestModule.addArtifactAttribute(values.get(0), BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ORGANIZATION, attributes);
            }
        }
        
        BlackboardArtifact artifact = null;
        
        if(hasAtleastOnePhoneOrEmailAttribute) {
            // All arguments are nullable so long as a required type is available 
            // in the attributes list, hence the hasAtleastOnePhoneOrEmailAttribute
            // check.
            artifact = helper.addContact(null, null, null, null, null, attributes);
            extractPhotos(vcard, abstractFile, artifact);
        } else if(!attributes.isEmpty()) {
            // If there are zero phone or email attributes, then this artifact cannot
            // be helped by the CommHelper (Invalid and illegal, according to its API).
            // Instead, just create the artifact manually.
   
            org.sleuthkit.datamodel.Blackboard tskBlackboard = tskCase.getBlackboard();
            // Create artifact if it doesn't already exist.
            if (!tskBlackboard.artifactExists(abstractFile, BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT, attributes)) {
                artifact = abstractFile.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CONTACT);
                artifact.addAttributes(attributes);
                
                extractPhotos(vcard, abstractFile, artifact);

                // Index the artifact for keyword search.
                try {
                    blackboard.postArtifact(artifact,  EmailParserModuleFactory.getModuleName());
                } catch (Blackboard.BlackboardException ex) {
                    logger.log(Level.SEVERE, "Unable to index blackboard artifact " + artifact.getArtifactID(), ex); //NON-NLS
                    MessageNotifyUtil.Notify.error(Bundle.VcardParser_addContactArtifact_indexError(), artifact.getDisplayName());
                }
            }
        }
        
        return artifact;
    }
    
    /**
     * Extract photos from a given VCard and add them as derived files.
     * 
     * @param vcard        The VCard from which to extract the photos.
     * @param abstractFile The file associated with the data.
     * 
     * @throws NoCurrentCaseException if there is no open case.
     */
    private void extractPhotos(VCard vcard, AbstractFile abstractFile, BlackboardArtifact artifact) throws NoCurrentCaseException {
        String parentFileName = getUniqueName(abstractFile);
        // Skip files that already have been extracted.
        try {
            String outputPath = getOutputFolderPath(parentFileName);
            if (new File(outputPath).exists()) {
                List<Photo> vcardPhotos = vcard.getPhotos();
                List<AbstractFile> derivedFilesCreated = new ArrayList<>();
                for (int i=0; i < vcardPhotos.size(); i++) {
                    Photo photo = vcardPhotos.get(i);

                    if (photo.getUrl() != null) {
                        // Skip this photo since its data is not embedded.
                        continue;
                    }

                    String type = photo.getType();
                    if (type == null) {
                        // Skip this photo since no type is defined.
                        continue;
                    }

                    // Get the file extension for the subtype.
                    type = type.toLowerCase();
                    if (type.startsWith("image/")) {
                        type = type.substring(6);
                    }
                    String extension = photoTypeExtensions.get(type);

                    // Read the photo data and create a derived file from it.
                    byte[] data = photo.getData();
                    String extractedFileName = String.format("photo_%d%s", i, extension == null ? "" : extension);
                    String extractedFilePath = Paths.get(outputPath, extractedFileName).toString();
                    try {
                        writeExtractedImage(extractedFilePath, data);
                        derivedFilesCreated.add(fileManager.addDerivedFile(extractedFileName, getFileRelativePath(parentFileName, extractedFileName), data.length,
                                abstractFile.getCtime(), abstractFile.getCrtime(), abstractFile.getAtime(), abstractFile.getAtime(),
                                true, artifact, null, EmailParserModuleFactory.getModuleName(), EmailParserModuleFactory.getModuleVersion(), "", TskData.EncodingType.NONE));
                    } catch (IOException | TskCoreException ex) {
                        logger.log(Level.WARNING, String.format("Could not write image to '%s' (id=%d).", extractedFilePath, abstractFile.getId()), ex); //NON-NLS
                    }
                }
                if (!derivedFilesCreated.isEmpty()) {
                    services.fireModuleContentEvent(new ModuleContentEvent(abstractFile));
                    context.addFilesToJob(derivedFilesCreated);
                }
            }
            else {
                logger.log(Level.INFO, String.format("Skipping photo extraction for file '%s' (id=%d), because it has already been processed.",
                        abstractFile.getName(), abstractFile.getId())); //NON-NLS
            }
        } catch (SecurityException ex) {
            logger.log(Level.WARNING, String.format("Could not create extraction folder for '%s' (id=%d).", parentFileName, abstractFile.getId()));
        }
    }
    
    /**
     * Writes image to the module output location.
     *
     * @param outputPath Path where images is written.
     * @param data       Byte representation of the data to be written to the
     *                   specified location.
     */
    private void writeExtractedImage(String outputPath, byte[] data) throws IOException {
        File outputFile = new File(outputPath);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(data);
    }
    
    /**
     * Creates a unique name for a file by concatenating the file name and the
     * file object id.
     *
     * @param file The file.
     *
     * @return The unique file name.
     */
    private String getUniqueName(AbstractFile file) {
        return file.getName() + "_" + file.getId();
    }
    
    /**
     * Gets the relative path to the file. The path is relative to the case
     * folder.
     *
     * @param fileName Name of the the file for which the path is to be
     *                 generated.
     *
     * @return The relative file path.
     */
    private String getFileRelativePath(String parentFileName, String fileName) throws NoCurrentCaseException {
        // Used explicit FWD slashes to maintain DB consistency across operating systems.
        return Paths.get(getRelModuleOutputPath(), parentFileName, fileName).toString();
    }
    
    /**
     * Gets path to the output folder for file extraction. If the path does not
     * exist, it is created.
     *
     * @param parentFileName Name of the abstract file being processed.
     * 
     * @throws NoCurrentCaseException if there is no open case.
     *
     * @return Path to the file extraction folder for a given abstract file.
     */
    private String getOutputFolderPath(String parentFileName) throws NoCurrentCaseException {
        String outputFolderPath = ThunderbirdMboxFileIngestModule.getModuleOutputPath() + File.separator + parentFileName;
        File outputFilePath = new File(outputFolderPath);
        if (!outputFilePath.exists()) {
            outputFilePath.mkdirs();
        }
        return outputFolderPath;
    }
    
    /**
     * Generate phone attributes for a given VCard Telephone object.
     * 
     * @param telephone    The VCard Telephone from which to generate attributes.
     * @param abstractFile The VCard file.
     * @param attributes   The Collection to which generated attributes will be
     *                     added.
     * 
     * @return True if a phone attribute was added, false otherwise.
     */
    private boolean addPhoneAttributes(Telephone telephone, AbstractFile abstractFile, Collection<BlackboardAttribute> attributes) {
        String telephoneText = telephone.getText();
       
        if (telephoneText == null || telephoneText.isEmpty()) {
            telephoneText =  telephone.getUri().getNumber();
            if (telephoneText == null || telephoneText.isEmpty()) {
                return false;
            }
        }

        // Add phone number to collection for later creation of TSK_CONTACT.
        List<TelephoneType> telephoneTypes = telephone.getTypes();
        if (telephoneTypes.isEmpty()) {
            ThunderbirdMboxFileIngestModule.addArtifactAttribute(telephone.getText(), BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER, attributes);
            return true;
        } else {
            TelephoneType type = telephoneTypes.get(0);
            /*
             * Unfortunately, if the types are lower-case, they don't
             * get separated correctly into individual TelephoneTypes by
             * ez-vcard. Therefore, we must read them manually
             * ourselves.
             */
            List<String> splitTelephoneTypes = Arrays.asList(
                    type.getValue().toUpperCase().replaceAll("\\s+","").split(","));

            if (splitTelephoneTypes.size() > 0) {
                String splitType = splitTelephoneTypes.get(0);
                String attributeTypeName = "TSK_PHONE_NUMBER";
                if (splitType != null && !splitType.isEmpty()) {
                    attributeTypeName = "TSK_PHONE_NUMBER_" + splitType;
                }

                try {
                    BlackboardAttribute.Type attributeType = tskCase.getAttributeType(attributeTypeName);
                    if (attributeType == null) {
                        try{
                            // Add this attribute type to the case database.
                            attributeType = tskCase.addArtifactAttributeType(attributeTypeName,
                                    BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                    String.format("Phone Number (%s)", StringUtils.capitalize(splitType.toLowerCase())));
                        }catch (TskDataException ex) {
                            attributeType = tskCase.getAttributeType(attributeTypeName);
                        }
                    }
                    ThunderbirdMboxFileIngestModule.addArtifactAttribute(telephoneText, attributeType, attributes);
                    return true;
                } catch (TskCoreException ex) {
                    logger.log(Level.WARNING, String.format("Unable to retrieve attribute type '%s' for file '%s' (id=%d).", attributeTypeName, abstractFile.getName(), abstractFile.getId()), ex);
                }
            } 
            return false;
        }
    }
    
    /**
     * Generate e-mail attributes for a given VCard Email object.
     * 
     * @param email        The VCard Email from which to generate attributes.
     * @param abstractFile The VCard file.
     * @param attributes   The Collection to which generated attributes will be
     *                     added.
     * @return True if an email attribute was added, false otherwise.
     */
    private boolean addEmailAttributes(Email email, AbstractFile abstractFile, Collection<BlackboardAttribute> attributes) {
        String emailValue = email.getValue();
        if (emailValue == null || emailValue.isEmpty()) {
            return false;
        }

        // Add phone number to collection for later creation of TSK_CONTACT.
        List<EmailType> emailTypes = email.getTypes();
        if (emailTypes.isEmpty()) {
            ThunderbirdMboxFileIngestModule.addArtifactAttribute(email.getValue(), BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL, attributes);
            return true;
        } else {
            EmailType type = emailTypes.get(0);                /*
            * Unfortunately, if the types are lower-case, they don't
            * get separated correctly into individual EmailTypes by
            * ez-vcard. Therefore, we must read them manually
            * ourselves.
            */
           List<String> splitEmailTypes = Arrays.asList(
                   type.getValue().toUpperCase().replaceAll("\\s+","").split(","));

           if (splitEmailTypes.size() > 0) {
               String splitType = splitEmailTypes.get(0);
               String attributeTypeName = "TSK_EMAIL_" + splitType;
               if(splitType.isEmpty()) {
                   attributeTypeName = "TSK_EMAIL";
               }
               try {
                   BlackboardAttribute.Type attributeType = tskCase.getAttributeType(attributeTypeName);
                   if (attributeType == null) {
                       // Add this attribute type to the case database.
                       attributeType = tskCase.addArtifactAttributeType(attributeTypeName, 
                               BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                               String.format("Email (%s)", StringUtils.capitalize(splitType.toLowerCase())));
                   }
                   ThunderbirdMboxFileIngestModule.addArtifactAttribute(email.getValue(), attributeType, attributes);
                   return true;
               } catch (TskCoreException ex) {
                   logger.log(Level.SEVERE, String.format("Unable to retrieve attribute type '%s' for file '%s' (id=%d).", attributeTypeName, abstractFile.getName(), abstractFile.getId()), ex);
               } catch (TskDataException ex) {
                   logger.log(Level.SEVERE, String.format("Unable to add custom attribute type '%s' for file '%s' (id=%d).", attributeTypeName, abstractFile.getName(), abstractFile.getId()), ex);
               }
           }
           return false;
        }
    }
}
