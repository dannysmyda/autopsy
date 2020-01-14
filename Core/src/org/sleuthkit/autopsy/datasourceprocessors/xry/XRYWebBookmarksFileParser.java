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
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.WebBrowserArtifactsHelper;

/**
 * Parses XRY Web-Bookmark files and creates artifacts.
 */
final class XRYWebBookmarksFileParser extends AbstractSingleEntityParser {

    @Override
    boolean canProcess(XRYKeyValuePair pair) {
        return XRYKey.contains(pair.getKey());
    }

    @Override
    boolean isNamespace(String nameSpace) {
        //No known namespaces for web reports.
        return false;
    }

    /**
     *
     * @param builder
     * @param pair
     */
    private void addToBuilder(WebBookmark.Builder builder, XRYKeyValuePair pair) {
        XRYKey xryKey = XRYKey.fromDisplayName(pair.getKey());
        switch (xryKey) {
            case APPLICATION:
                builder.setProgName(pair.getValue());
                break;
            case WEB_ADDRESS:
                builder.setUrl(pair.getValue());
                break;
            default:
                builder.addOtherAttributes(new BlackboardAttribute(
                        xryKey.getType(), PARSER_NAME,
                        pair.getValue()
                ));
        }
    }

    @Override
    void makeArtifact(List<XRYKeyValuePair> keyValuePairs, Content parent, SleuthkitCase currentCase) throws TskCoreException, BlackboardException {
        WebBookmark.Builder builder = new WebBookmark.Builder();

        for (XRYKeyValuePair pair : keyValuePairs) {
            addToBuilder(builder, pair);
        }

        if (builder.hasRequiredFields()) {
            WebBookmark webBookmark = builder.build();
            WebBrowserArtifactsHelper helper = new WebBrowserArtifactsHelper(
                    currentCase, "XRY DSP", parent);

            helper.addWebBookmark(
                    webBookmark.getUrl(),
                    webBookmark.getTitle(),
                    webBookmark.getCreationTime(),
                    webBookmark.getProgName(),
                    webBookmark.getOtherAttributes()
            );
        }
    }

    /**
     * 
     */
    private static class WebBookmark {

        private final WebBookmark.Builder builder;

        private WebBookmark(WebBookmark.Builder webBookmarkBuilder) {
            builder = webBookmarkBuilder;
        }

        private String getUrl() {
            return this.builder.url;
        }

        private String getTitle() {
            return this.builder.title;
        }

        private long getCreationTime() {
            return this.builder.creationTime;
        }

        private String getProgName() {
            return this.builder.progName;
        }

        private Collection<BlackboardAttribute> getOtherAttributes() {
            return this.builder.otherAttributes;
        }

        //Manages and aggregates all of the parameters that will be used
        //to call CommunicationArtifactsHelper.addCalllog.
        private static class Builder {

            private String url;
            private String title;
            private long creationTime;
            private String progName;
            private final Collection<BlackboardAttribute> otherAttributes;

            private Builder() {
                url = "";
                title = "";
                creationTime = 0;
                progName = "";
                otherAttributes = new ArrayList<>();
            }

            private void setUrl(String url) {
                this.url = url;
            }

            private void setProgName(String progName) {
                this.progName = progName;
            }

            private void addOtherAttributes(BlackboardAttribute attr) {
                otherAttributes.add(attr);
            }

            private boolean hasRequiredFields() {
                //Only the URL field is needed.
                return !url.isEmpty();
            }

            private WebBookmark build() {
                return new WebBookmark(this);
            }
        }
    }
    
    /**
     * All of the known keys for web bookmark reports.
     */
    private enum XRYKey {
        APPLICATION("application", null),
        DOMAIN("domain", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN),
        WEB_ADDRESS("web address", null);

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
