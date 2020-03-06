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

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalQueries;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper.CallMediaType;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper.CommunicationDirection;

/**
 * Parses XRY Calls files and creates artifacts.
 */
final class XRYCallsFileParser extends AbstractSingleEntityParser {

    private static final Logger logger = Logger.getLogger(XRYCallsFileParser.class.getName());

    //Pattern is in reverse due to a Java 8 bug, see calculateSecondsSinceEpoch()
    //function for more details.
    private static final DateTimeFormatter DATE_TIME_PARSER
            = DateTimeFormatter.ofPattern("[(XXX) ][O ][(O) ]a h:m:s M/d/y");

    private static final String DEVICE_LOCALE = "(device)";
    private static final String NETWORK_LOCALE = "(network)";

    /**
     * All of the known XRY keys for call reports and their corresponding
     * blackboard attribute types, if any.
     */
    private enum XryKey {
        NAME_MATCHED("name (matched)", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME),
        TIME("time", null),
        DIRECTION("direction", null),
        CALL_TYPE("call type", null),
        NUMBER("number", null),
        TEL("tel", null),
        TO("to", null),
        FROM("from", null),
        DELETED("deleted", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ISDELETED),
        DURATION("duration", null),
        STORAGE("storage", null),
        INDEX("index", null),
        TYPE("type", null),
        NAME("name", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME);

        private final String name;
        private final BlackboardAttribute.ATTRIBUTE_TYPE type;

        XryKey(String name, BlackboardAttribute.ATTRIBUTE_TYPE type) {
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
                XryKey.fromDisplayName(key);
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
        public static XryKey fromDisplayName(String key) {
            String normalizedKey = key.trim().toLowerCase();
            for (XryKey keyChoice : XryKey.values()) {
                if (normalizedKey.equals(keyChoice.name)) {
                    return keyChoice;
                }
            }

            throw new IllegalArgumentException(String.format("Key [%s] was not found."
                    + " All keys should be tested with contains.", key));
        }
    }

    /**
     * All known XRY namespaces for call reports.
     */
    private enum XryNamespace {
        TO("to"),
        FROM("from"),
        NONE(null);

        private final String name;

        XryNamespace(String name) {
            this.name = name;
        }

        /**
         * Indicates if the display name of the XRY namespace is a recognized
         * type.
         */
        public static boolean contains(String xryNamespace) {
            try {
                XryNamespace.fromDisplayName(xryNamespace);
                return true;
            } catch (IllegalArgumentException ex) {
                return false;
            }
        }

        /**
         * Matches the display name of the xry namespace to the appropriate enum
         * type.
         *
         * It is assumed that XRY namespace string is recognized. Otherwise, an
         * IllegalArgumentException is thrown. Test all membership with
         * contains() before hand.
         */
        public static XryNamespace fromDisplayName(String xryNamespace) {
            String normalizedNamespace = xryNamespace.trim().toLowerCase();
            for (XryNamespace keyChoice : XryNamespace.values()) {
                if (normalizedNamespace.equals(keyChoice.name)) {
                    return keyChoice;
                }
            }

            throw new IllegalArgumentException(String.format("Key [%s] was not found."
                    + " All keys should be tested with contains.", xryNamespace));
        }
    }

    @Override
    boolean canProcess(XRYKeyValuePair pair) {
        return XryKey.contains(pair.getKey());
    }

    @Override
    boolean isNamespace(String nameSpace) {
        return XryNamespace.contains(nameSpace);
    }

    @Override
    void makeArtifact(List<XRYKeyValuePair> keyValuePairs, Content parent, SleuthkitCase currentCase) throws TskCoreException, BlackboardException {
        // Transform all the data from XRY land into the appropriate CommHelper
        // data types.
        String callerId = null;
        final Collection<String> calleeList = new ArrayList<>();
        CommunicationDirection direction = CommunicationDirection.UNKNOWN;
        long startTime = 0L;
        final long endTime = 0L;
        final CallMediaType callType = CallMediaType.UNKNOWN;
        final Collection<BlackboardAttribute> otherAttributes = new ArrayList<>();

        for (XRYKeyValuePair pair : keyValuePairs) {
            XryKey xryKey = XryKey.fromDisplayName(pair.getKey());
            XryNamespace xryNamespace = XryNamespace.NONE;
            if (XryNamespace.contains(pair.getNamespace())) {
                xryNamespace = XryNamespace.fromDisplayName(pair.getNamespace());
            }

            switch (xryKey) {
                case TEL:
                case NUMBER:
                    //Apply the namespace
                    switch (xryNamespace) {
                        case FROM:
                            if(callerId != null) {
                                otherAttributes.add(new BlackboardAttribute(
                                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM,
                                    PARSER_NAME, pair.getValue()));
                            } else {
                                callerId = pair.getValue();
                            }
                            break;
                        case TO:
                            calleeList.add(pair.getValue());
                            break;
                        default:
                            otherAttributes.add(new BlackboardAttribute(
                                    BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER,
                                    PARSER_NAME, pair.getValue()));
                    }
                    break;
                //Although confusing, as these are also 'name spaces', it appears
                //later versions of XRY realized having standardized lines was easier
                //to read.
                case TO:
                    calleeList.add(pair.getValue());
                    break;
                case FROM:
                    if(callerId != null) {
                        otherAttributes.add(new BlackboardAttribute(
                            BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM,
                            PARSER_NAME, pair.getValue()));
                    } else {
                        callerId = pair.getValue();
                    }
                    break;
                case TIME:
                    try {
                        //Tranform value to seconds since epoch
                        long dateTimeSinceEpoch = calculateSecondsSinceEpoch(pair.getValue());
                        startTime = dateTimeSinceEpoch;
                    } catch (DateTimeParseException ex) {
                        logger.log(Level.WARNING, String.format("[XRY DSP] Assumption"
                                + " about the date time formatting of call logs is "
                                + "not right. Here is the value [ %s ]", pair.getValue()), ex);
                    }
                    break;
                case DIRECTION:
                    String directionString = pair.getValue().toLowerCase();
                    if (directionString.equals("incoming")) {
                        direction = CommunicationDirection.INCOMING;
                    } else {
                        direction = CommunicationDirection.OUTGOING;
                    }
                    break;
                default:
                    //Otherwise, the XryKey enum contains the correct BlackboardAttribute
                    //type.
                    if (xryKey.getType() != null) {
                        otherAttributes.add(new BlackboardAttribute(xryKey.getType(),
                                PARSER_NAME, pair.getValue()));
                    }

                    logger.log(Level.INFO, String.format("[XRY DSP] Key value pair "
                            + "(in brackets) [ %s ] was recognized but "
                            + "more data or time is needed to finish implementation. Discarding... ",
                            pair));
            }
        }

        // Make sure we have the required fields, otherwise the CommHelper will
        // complain about illegal arguments.
        if (callerId != null || !calleeList.isEmpty()) {
            CommunicationArtifactsHelper helper = new CommunicationArtifactsHelper(
                    currentCase, PARSER_NAME, parent, Account.Type.DEVICE);

            helper.addCalllog(direction, callerId, calleeList, startTime,
                    endTime, callType, otherAttributes);
        } else {
            // Otherwise, just make an artifact with what we've got.
            if(direction != CommunicationDirection.UNKNOWN) {
                otherAttributes.add(new BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION,
                    PARSER_NAME, direction.getDisplayName()));
            }
            
            if(startTime > 0L) {
                otherAttributes.add(new BlackboardAttribute(
                        BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_START,
                    PARSER_NAME, startTime));
            }
            
            if(!otherAttributes.isEmpty()) {
                BlackboardArtifact artifact = parent.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_CALLLOG);
                artifact.addAttributes(otherAttributes);
                
                currentCase.getBlackboard().postArtifact(artifact, PARSER_NAME);
            }
        }
    }

    /**
     * Removes the locale from the date time value.
     *
     * Locale in this case being (Device) or (Network).
     *
     * @param dateTime XRY datetime value to be sanitized.
     * @return A purer date time value.
     */
    private String removeDateTimeLocale(String dateTime) {
        String result = dateTime;
        int deviceIndex = result.toLowerCase().indexOf(DEVICE_LOCALE);
        if (deviceIndex != -1) {
            result = result.substring(0, deviceIndex);
        }
        int networkIndex = result.toLowerCase().indexOf(NETWORK_LOCALE);
        if (networkIndex != -1) {
            result = result.substring(0, networkIndex);
        }
        return result;
    }

    /**
     * Parses the date time value and calculates seconds since epoch.
     *
     * @param dateTime
     * @return
     */
    private long calculateSecondsSinceEpoch(String dateTime) {
        String dateTimeWithoutLocale = removeDateTimeLocale(dateTime).trim();
        /**
         * The format of time in XRY Messages reports is of the form:
         *
         * 1/3/1990 1:23:54 AM UTC+4
         *
         * In our current version of Java (openjdk-1.8.0.222), there is a bug
         * with having the timezone offset (UTC+4 or GMT-7) at the end of the
         * date time input. This is fixed in later versions of the JDK (9 and
         * beyond). https://bugs.openjdk.java.net/browse/JDK-8154050 Rather than
         * update the JDK to accommodate this, the components of the date time
         * string are reversed:
         *
         * UTC+4 AM 1:23:54 1/3/1990
         *
         * The java time package will correctly parse this date time format.
         */
        String reversedDateTime = reverseOrderOfDateTimeComponents(dateTimeWithoutLocale);
        /**
         * Furthermore, the DateTimeFormatter's timezone offset letter ('O')
         * does not recognize UTC but recognizes GMT. According to
         * https://en.wikipedia.org/wiki/Coordinated_Universal_Time, GMT only
         * differs from UTC by at most 1 second and so substitution will only
         * introduce a trivial amount of error.
         */
        String reversedDateTimeWithGMT = reversedDateTime.replace("UTC", "GMT");
        TemporalAccessor result = DATE_TIME_PARSER.parseBest(reversedDateTimeWithGMT,
                ZonedDateTime::from,
                LocalDateTime::from,
                OffsetDateTime::from);
        //Query for the ZoneID
        if (result.query(TemporalQueries.zoneId()) == null) {
            //If none, assumed GMT+0.
            return ZonedDateTime.of(LocalDateTime.from(result),
                    ZoneId.of("GMT")).toEpochSecond();
        } else {
            return Instant.from(result).getEpochSecond();
        }
    }

    /**
     * Reverses the order of the date time components.
     *
     * Example: 1/3/1990 1:23:54 AM UTC+4 becomes UTC+4 AM 1:23:54 1/3/1990
     *
     * @param dateTime
     * @return
     */
    private String reverseOrderOfDateTimeComponents(String dateTime) {
        StringBuilder reversedDateTime = new StringBuilder(dateTime.length());
        String[] dateTimeComponents = dateTime.split(" ");
        for (String component : dateTimeComponents) {
            reversedDateTime.insert(0, " ").insert(0, component);
        }
        return reversedDateTime.toString().trim();
    }
}
