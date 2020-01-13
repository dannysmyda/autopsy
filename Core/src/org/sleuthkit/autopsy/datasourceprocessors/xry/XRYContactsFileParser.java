/*
 * Autopsy Forensic Browser
 *
 * Copyright 2019-2020 Basis Technology Corp.
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
package org.sleuthkit.autopsy.datasourceprocessors.xry;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper;

/**
 * Parses XRY Contacts-Contacts files and creates artifacts.
 */
final class XRYContactsFileParser extends AbstractSingleEntityParser {

    private static final Logger logger = Logger.getLogger(XRYContactsFileParser.class.getName());

    @Override
    boolean canProcess(XRYKeyValuePair pair) {
        return XRYKey.contains(pair.getKey());
    }

    @Override
    boolean isNamespace(String nameSpace) {
        //No namespaces are currently known for this report type.
        return false;
    }

    /**
     *
     * @param builder
     * @param pair
     */
    private void addToBuilder(Contact.Builder builder, XRYKeyValuePair pair) {
        XRYKey xryKey = XRYKey.fromDisplayName(pair.getKey());
        switch (xryKey) {
            case NAME:
                builder.setName(pair.getValue());
                break;
            case TEL:
                builder.setPhoneNumber(pair.getValue());
                break;
            case MOBILE:
                builder.setMobilePhoneNumber(pair.getValue());
                break;
            case HOME:
                builder.setHomePhoneNumber(pair.getValue());
                break;
            default:
                if (xryKey.getType() != null) {
                    builder.addOtherAttributes(new BlackboardAttribute(
                            xryKey.getType(), PARSER_NAME, pair.getValue()));
                } else {
                    logger.log(Level.INFO, String.format("[XRY DSP] Key value pair "
                            + "(in brackets) [ %s ] was recognized but we need "
                            + "more data or time to finish implementation. Discarding... ",
                            pair));
                }
        }
    }

    @Override
    void makeArtifact(List<XRYKeyValuePair> keyValuePairs, Content parent, SleuthkitCase currentCase) throws TskCoreException, Blackboard.BlackboardException {
        Contact.Builder builder = new Contact.Builder();

        for (XRYKeyValuePair pair : keyValuePairs) {
            addToBuilder(builder, pair);
        }

        if (!builder.isEmpty()) {
            Contact contact = builder.build();
            CommunicationArtifactsHelper helper = new CommunicationArtifactsHelper(
                    currentCase, "XRY DSP", parent, Account.Type.DEVICE);

            helper.addContact(
                    contact.getName(),
                    contact.getPhoneNumber(),
                    contact.getHomePhoneNumber(),
                    contact.getMobilePhoneNumber(),
                    contact.getEmailAddress(),
                    contact.getOtherAttributes()
            );
        }
    }

    /**
     * 
     */
    private static class Contact {

        private final Contact.Builder builder;

        private Contact(Contact.Builder contactBuilder) {
            builder = contactBuilder;
        }

        private String getName() {
            return this.builder.name;
        }

        private String getPhoneNumber() {
            return this.builder.phoneNumber;
        }

        private String getHomePhoneNumber() {
            return this.builder.homePhoneNumber;
        }

        private String getMobilePhoneNumber() {
            return this.builder.mobilePhoneNumber;
        }

        private String getEmailAddress() {
            return this.builder.emailAddress;
        }

        private Collection<BlackboardAttribute> getOtherAttributes() {
            return this.builder.otherAttributes;
        }

        //Manages and aggregates all of the parameters that will be used
        //to call CommunicationArtifactsHelper.addCalllog.
        private static class Builder {

            private String name;
            private String phoneNumber;
            private String homePhoneNumber;
            private String mobilePhoneNumber;
            private String emailAddress;
            private final Collection<BlackboardAttribute> otherAttributes;

            public Builder() {
                name = "";
                phoneNumber = "";
                homePhoneNumber = "";
                mobilePhoneNumber = "";
                emailAddress = "";
                otherAttributes = new ArrayList<>();
            }

            private void setName(String name) {
                this.name = name;
            }

            private void setPhoneNumber(String phoneNumber) {
                this.phoneNumber = phoneNumber;
            }

            private void setHomePhoneNumber(String homePhone) {
                this.homePhoneNumber = homePhone;
            }

            private void setMobilePhoneNumber(String mobilePhone) {
                this.mobilePhoneNumber = mobilePhone;
            }

            private void addOtherAttributes(BlackboardAttribute attr) {
                otherAttributes.add(attr);
            }

            private boolean isEmpty() {
                return name.isEmpty() && phoneNumber.isEmpty()
                        && otherAttributes.isEmpty() && homePhoneNumber.isEmpty()
                        && mobilePhoneNumber.isEmpty() && emailAddress.isEmpty();
            }

            private Contact build() {
                return new Contact(this);
            }
        }
    }
    
    private enum XRYKey {
        NAME("name", null),
        TEL("tel", null),
        MOBILE("mobile", null),
        HOME("home", null),
        RELATED_APPLICATION("related application", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME),
        ADDRESS_HOME("address home", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LOCATION),
        EMAIL_HOME("email home", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_EMAIL_HOME),
        DELETED("deleted", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ISDELETED),
        //Ignoring or need more information to decide.
        STORAGE("storage", null),
        OTHER("other", null),
        PICTURE("picture", null),
        INDEX("index", null),
        ACCOUNT_NAME("account name", null);

        private final String name;
        private final BlackboardAttribute.ATTRIBUTE_TYPE type;

        XRYKey(String name, BlackboardAttribute.ATTRIBUTE_TYPE type) {
            this.name = name;
            this.type = type;
        }

        public BlackboardAttribute.ATTRIBUTE_TYPE getType() {
            return type;
        }

        /**
         * Indicates if the display name of the XRY key is a recognized type.
         */
        public static boolean contains(String key) {
            try {
                XRYKey.fromDisplayName(key);
                return true;
            } catch (IllegalArgumentException ex) {
                return false;
            }
        }

        /**
         * Matches the display name of the xry key to the appropriate enum type.
         *
         * It is assumed that XRY key string is recognized. Otherwise, an
         * IllegalArgumentException is thrown. Test all membership with
         * contains() before hand.
         */
        public static XRYKey fromDisplayName(String key) {
            String normalizedKey = key.trim().toLowerCase();
            for (XRYKey keyChoice : XRYKey.values()) {
                if (normalizedKey.equals(keyChoice.name)) {
                    return keyChoice;
                }
            }

            throw new IllegalArgumentException(String.format("Key [%s] was not found."
                    + " All keys should be tested with contains.", key));
        }
    }
}
