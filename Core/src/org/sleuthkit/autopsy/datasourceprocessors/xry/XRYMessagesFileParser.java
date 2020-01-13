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

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;
import java.time.temporal.TemporalQueries;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Queue;
import java.util.Set;
import java.util.logging.Level;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.datamodel.Account;
import org.sleuthkit.datamodel.Blackboard.BlackboardException;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper.CommunicationDirection;
import org.sleuthkit.datamodel.blackboardutils.CommunicationArtifactsHelper.MessageReadStatus;

/**
 * Parses Messages-SMS files and creates artifacts.
 */
final class XRYMessagesFileParser implements XRYFileParser {

    private static final Logger logger = Logger.getLogger(
            XRYMessagesFileParser.class.getName());

    private static final String PARSER_NAME = "XRY DSP";

    //Pattern is in reverse due to a Java 8 bug, see calculateSecondsSinceEpoch()
    //function for more details.
    private static final DateTimeFormatter DATE_TIME_PARSER
            = DateTimeFormatter.ofPattern("[(XXX) ][O ][(O) ]a h:m:s M/d/y");

    private static final String DEVICE_LOCALE = "(device)";
    private static final String NETWORK_LOCALE = "(network)";

    /**
     * Parses each XRY Entity in a Message-SMS report. Message-SMS Entities have
     * a few special properties. For one, their 'Text' key can span multiple
     * lines. The underlying message from the device may also be segmented
     * across multiple entities. Our goal in this parser is to reconstruct the
     * segmented message and submit this as one artifact. Given these
     * requirements and the breadth of attributes supported for Message-SMS
     * reports, this is by far the most complicated report parser.
     *
     * @param reader The XRYFileReader that reads XRY entities from the
     * Message-SMS report.
     * @param parent The parent Content to create artifacts from.
     * @throws IOException If an I/O error is encountered during report reading
     * @throws TskCoreException If an error during artifact creation is
     * encountered.
     */
    @Override
    public void parse(XRYFileReader reader, Content parent, SleuthkitCase currentCase) throws IOException, TskCoreException, BlackboardException {
        Path reportPath = reader.getReportPath();
        logger.log(Level.INFO, String.format("[%s] Processing report at"
                + " [ %s ]", PARSER_NAME, reportPath.toString()));

        //Keep track of the reference numbers that have been parsed.
        Set<Integer> referenceNumbersSeen = new HashSet<>();

        while (reader.hasNextEntity()) {
            String xryEntity = reader.nextEntity();
            List<XRYKeyValuePair> pairs = getXRYKeyValuePairs(xryEntity, reader, referenceNumbersSeen);

            Message.Builder builder = new Message.Builder(PARSER_NAME);
            for (XRYKeyValuePair pair : pairs) {
                addToBuilder(builder, pair);
            }

            if (!builder.isEmpty()) {
                Message message = builder.build();
                CommunicationArtifactsHelper helper = new CommunicationArtifactsHelper(
                        currentCase, PARSER_NAME, parent, Account.Type.DEVICE);

                helper.addMessage(
                        message.getMessageType(),
                        message.getDirection(),
                        message.getSenderId(),
                        message.getRecipientIdsList(),
                        message.getDateTime(),
                        message.getReadStatus(),
                        message.getSubject(),
                        message.getText(),
                        message.getThreadId(),
                        message.getOtherAttributes()
                );
            }
        }
    }

    /**
     *
     * @param xryEntity
     * @param reader
     * @param referenceValues
     * @return
     * @throws IOException
     */
    private List<XRYKeyValuePair> getXRYKeyValuePairs(String xryEntity,
            XRYFileReader reader, Set<Integer> referenceValues) throws IOException {

        Queue<String> xryLines = new ArrayDeque<>(Arrays.asList(xryEntity.split("\n")));
        //First line of the entity is the title, each XRY entity is non-empty.
        logger.log(Level.INFO, String.format("[%s] Processing [ %s ]", PARSER_NAME, xryLines.poll()));

        List<XRYKeyValuePair> result = new ArrayList<>();
        String namespace = "";
        while (!xryLines.isEmpty()) {
            String xryLine = xryLines.poll();
            if (XryNamespace.contains(xryLine)) {
                namespace = xryLine.trim();
                continue;
            } else if (!XRYKeyValuePair.isPair(xryLine)) {
                logger.log(Level.SEVERE, String.format("[%s] Expected a key value "
                        + "pair on this line (in brackets) [ %s ], but one was not detected."
                        + " Discarding...", PARSER_NAME, xryLine));
                continue;
            }

            XRYKeyValuePair pair = XRYKeyValuePair.from(xryLine, namespace);
            if (validatePair(pair)) {
                StringBuilder builder = new StringBuilder(pair.getValue());
                buildMultiLineValue(builder, xryLines);

                //'text' and 'message' fields can be segmented
                //among multiple XRY entities.
                if (pair.hasKey(XryKey.TEXT.getDisplayName())
                        || pair.hasKey(XryKey.MESSAGE.getDisplayName())) {
                    //Reuse the same builder to add any segmented text.
                    buildSegmentedText(xryEntity, reader, referenceValues, builder);
                }

                pair = new XRYKeyValuePair(pair.getKey(), builder.toString(), pair.getNamespace());
                result.add(pair);
            }
        }

        return result;
    }

    /**
     *
     * @param builder
     * @param lines
     */
    private void buildMultiLineValue(StringBuilder builder, Queue<String> lines) {
        while (!lines.isEmpty()
                && !XRYKeyValuePair.isPair(lines.peek())
                && !XryNamespace.contains(lines.peek())) {
            builder.append(" ").append(lines.poll().trim());
        }
    }

    /**
     *
     * @param pair
     * @return
     */
    private boolean validatePair(XRYKeyValuePair pair) {
        if (XryMetaKey.contains(pair.getKey())) {
            //Meta Keys are handled differently.
            return false;
        } else if (!XryKey.contains(pair.getKey())) {
            logger.log(Level.WARNING, String.format("[%s] The following key, "
                    + "value pair (in brackets) [ %s ], "
                    + "was not recognized. Discarding...", PARSER_NAME, pair));
            return false;
        } else if (pair.getValue().isEmpty()) {
            logger.log(Level.WARNING, String.format("[%s] The following key "
                    + "(in brackets) [ %s ] was recognized, but the value "
                    + "was empty. Discarding...", PARSER_NAME, pair.getKey()));
            return false;
        }
        return true;
    }

    /**
     * Builds up segmented message entities so that the text is unified for a
     * single artifact.
     *
     * @param reader File reader that is producing XRY entities.
     * @param referenceNumbersSeen All known references numbers up until this
     * point.
     * @param xryEntity The source XRY entity.
     * @return
     * @throws IOException
     */
    private void buildSegmentedText(String xryEntity, XRYFileReader reader,
            Set<Integer> referenceNumbersSeen, StringBuilder builder) throws IOException {
        String[] xryLines = xryEntity.split("\n");
        Optional<Integer> referenceNumber = getMetaKeyValue(xryLines, XryMetaKey.REFERENCE_NUMBER);
        //Check if there is any segmented text.
        if (!referenceNumber.isPresent()) {
            return;
        }

        logger.log(Level.INFO, String.format("[%s] Message entity "
                + "appears to be segmented with reference number [ %d ]", 
                PARSER_NAME, referenceNumber.get()));

        if (referenceNumbersSeen.contains(referenceNumber.get())) {
            logger.log(Level.SEVERE, String.format("[%s] This reference [ %d ] has already "
                    + "been seen. This means that the segments are not "
                    + "contiguous. Any segments contiguous with this "
                    + "one will be aggregated and another "
                    + "(otherwise duplicate) artifact will be created.",
                    PARSER_NAME, referenceNumber.get()));
        }

        referenceNumbersSeen.add(referenceNumber.get());

        Optional<Integer> segmentNumber = getMetaKeyValue(xryLines, XryMetaKey.SEGMENT_NUMBER);
        if (!segmentNumber.isPresent()) {
            logger.log(Level.SEVERE, String.format("[%s] No segment "
                    + "number was found on the message entity"
                    + "with reference number [%d]", PARSER_NAME, referenceNumber.get()));
            return;
        }

        int currentSegmentNumber = segmentNumber.get();
        while (reader.hasNextEntity()) {
            //Peek at the next to see if it has the same reference number.
            String nextEntity = reader.peek();
            String[] nextEntityLines = nextEntity.split("\n");
            Optional<Integer> nextReferenceNumber = getMetaKeyValue(nextEntityLines, XryMetaKey.REFERENCE_NUMBER);
            Optional<Integer> nextSegmentNumber = getMetaKeyValue(nextEntityLines, XryMetaKey.SEGMENT_NUMBER);

            if (!nextReferenceNumber.isPresent()
                    || !Objects.equals(nextReferenceNumber, referenceNumber)) {
                //Don't consume the next entity. It is not related
                //to the current message thread.
                break;
            }

            //Consume the entity, it is a part of the message thread.
            reader.nextEntity();
            Queue<String> nextXryEntityLines = new ArrayDeque<>(Arrays.asList(nextEntityLines));
            logger.log(Level.INFO, String.format("[%s] Processing [ %s ] "
                    + "segment with reference number [ %d ]",PARSER_NAME, 
                    nextXryEntityLines.poll(), referenceNumber.get()));

            if (!nextSegmentNumber.isPresent()) {
                logger.log(Level.SEVERE, String.format("[%s] Segment with reference"
                        + " number [ %d ] did not have a segment number associated with it."
                        + " It cannot be determined if the reconstructed text will be in order.", 
                        PARSER_NAME, referenceNumber.get()));
            } else if (nextSegmentNumber.get() != currentSegmentNumber + 1) {
                logger.log(Level.SEVERE, String.format("[%s] Contiguous "
                        + "segments are not ascending incrementally. Encountered "
                        + "segment [ %d ] after segment [ %d ]. This means the reconstructed "
                        + "text will be out of order.", PARSER_NAME, 
                        nextSegmentNumber.get(), currentSegmentNumber));
            }

            while (!nextXryEntityLines.isEmpty()) {
                String nextXryEntityLine = nextXryEntityLines.poll();
                //We are searching for TEXT and MESSAGE pairs, continue if 
                //this line is not a pair.
                if (!XRYKeyValuePair.isPair(nextXryEntityLine)) {
                    continue;
                }

                XRYKeyValuePair pair = XRYKeyValuePair.from(nextXryEntityLine);

                if (pair.hasKey(XryKey.TEXT.getDisplayName())
                        || pair.hasKey(XryKey.MESSAGE.getDisplayName())) {
                    builder.append(" ").append(pair.getValue());
                    //Build up multi-line text.
                    buildMultiLineValue(builder, nextXryEntityLines);
                }
            }

            if (nextSegmentNumber.isPresent()) {
                currentSegmentNumber = nextSegmentNumber.get();
            }
        }
    }

    /**
     * Extracts the value of the XRY meta key, if any.
     *
     * @param xryLines XRY entity to extract from.
     * @param metaKey The key type to extract.
     * @return
     */
    private Optional<Integer> getMetaKeyValue(String[] xryLines, XryMetaKey metaKey) {
        for (String xryLine : xryLines) {
            if (!XRYKeyValuePair.isPair(xryLine)) {
                continue;
            }

            XRYKeyValuePair pair = XRYKeyValuePair.from(xryLine);
            if (pair.hasKey(metaKey.getDisplayName())) {
                try {
                    return Optional.of(Integer.parseInt(pair.getValue()));
                } catch (NumberFormatException ex) {
                    logger.log(Level.SEVERE, String.format("[%s] Value [ %s ] for "
                            + "meta key [ %s ] was not an integer.", PARSER_NAME, 
                            pair.getValue(), metaKey), ex);
                }
            }
        }
        return Optional.empty();
    }

    private void addToBuilder(Message.Builder builder, XRYKeyValuePair pair) {
        XryNamespace namespace = XryNamespace.NONE;
        if (XryNamespace.contains(pair.getNamespace())) {
            namespace = XryNamespace.fromDisplayName(pair.getNamespace());
        }
        XryKey key = XryKey.fromDisplayName(pair.getKey());
        String normalizedValue = pair.getValue().toLowerCase().trim();

        switch (key) {
            case TEL:
            case NUMBER:
                switch (namespace) {
                    case FROM:
                        builder.setSenderId(pair.getValue());
                        break;
                    case TO:
                    case PARTICIPANT:
                        builder.addRecipientId(pair.getValue());
                        break;
                    default:
                        builder.addOtherAttributes(new BlackboardAttribute(
                                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER,
                                PARSER_NAME, pair.getValue()));
                }
                break;
            //Although confusing, as these are also 'name spaces', it appears
            //later versions of XRY realized having standardized lines was easier
            //to read.
            case FROM:
                builder.setSenderId(pair.getValue());
                break;
            case TO:
                builder.addRecipientId(pair.getValue());
                break;
            case TIME:
                try {
                    //Tranform value to seconds since epoch
                    long dateTimeSinceInEpoch = calculateSecondsSinceEpoch(pair.getValue());
                    builder.setDateTime(dateTimeSinceInEpoch);
                } catch (DateTimeParseException ex) {
                    logger.log(Level.WARNING, String.format("[%s] Assumption"
                            + " about the date time formatting of messages is "
                            + "not right. Here is the pair [ %s ]", PARSER_NAME, pair), ex);
                }
                break;
            case TYPE:
                switch (normalizedValue) {
                    case "incoming":
                        builder.setDirection(CommunicationDirection.INCOMING);
                        break;
                    case "outgoing":
                        builder.setDirection(CommunicationDirection.OUTGOING);
                        break;
                    case "deliver":
                    case "submit":
                    case "status report":
                        //Ignore for now.
                        break;
                    default:
                        logger.log(Level.WARNING, String.format("[%s] Unrecognized "
                                + " value for key pair [ %s ].", PARSER_NAME, pair));
                }
                break;
            case STATUS:
                switch (normalizedValue) {
                    case "read":
                        builder.setReadStatus(MessageReadStatus.READ);
                        break;
                    case "unread":
                        builder.setReadStatus(MessageReadStatus.UNREAD);
                        break;
                    case "deleted":
                        builder.addOtherAttributes(new BlackboardAttribute(
                                BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ISDELETED, 
                                PARSER_NAME, pair.getValue()));
                        break;
                    case "sending failed":
                    case "unsent":
                    case "sent":
                        //Ignoring for now.
                        break;
                    default:
                        logger.log(Level.WARNING, String.format("[%s] Unrecognized "
                                + " value for key pair [ %s ].", PARSER_NAME, pair));
                }
                break;
            case TEXT:
            case MESSAGE:
                builder.setText(pair.getValue());
                break;
            default:
                //Otherwise, the XryKey enum contains the correct BlackboardAttribute
                //type.
                if (key.getType() != null) {
                    builder.addOtherAttributes(new BlackboardAttribute(key.getType(),
                            PARSER_NAME, pair.getValue()));
                } else {
                    logger.log(Level.INFO, String.format("[%s] Key value pair "
                        + "(in brackets) [ %s ] was recognized but "
                        + "more data or time is needed to finish implementation. Discarding... ", 
                            PARSER_NAME, pair));
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

    /**
     *
     */
    private static class Message {

        private final Message.Builder builder;

        private Message(Message.Builder messageBuilder) {
            builder = messageBuilder;
        }

        private String getMessageType() {
            return this.builder.messageType;
        }

        private CommunicationDirection getDirection() {
            return this.builder.direction;
        }

        private String getSenderId() {
            return this.builder.senderId;
        }

        private List<String> getRecipientIdsList() {
            return this.builder.recipientIdsList;
        }

        private long getDateTime() {
            return this.builder.dateTime;
        }

        private MessageReadStatus getReadStatus() {
            return this.builder.readStatus;
        }

        private String getSubject() {
            return this.builder.subject;
        }

        private String getText() {
            return this.builder.text;
        }

        private String getThreadId() {
            return this.builder.threadId;
        }

        private Collection<BlackboardAttribute> getOtherAttributes() {
            return this.builder.otherAttributes;
        }

        private static class Builder {

            private String messageType;
            private CommunicationDirection direction;
            private String senderId;
            private final List<String> recipientIdsList;
            private long dateTime;
            private MessageReadStatus readStatus;
            private String subject;
            private String text;
            private String threadId;
            private final Collection<BlackboardAttribute> otherAttributes;

            public Builder(String messageType) {
                this.messageType = messageType;
                this.direction = CommunicationDirection.UNKNOWN;
                this.senderId = "";
                this.recipientIdsList = new ArrayList<>();
                this.dateTime = 0L;
                this.readStatus = MessageReadStatus.UNKNOWN;
                this.subject = "";
                this.text = "";
                this.threadId = "";
                this.otherAttributes = new ArrayList<>();
            }

            private void setDirection(CommunicationDirection direction) {
                this.direction = direction;
            }

            private void setSenderId(String senderId) {
                this.senderId = senderId;
            }

            private void addRecipientId(String recipientId) {
                this.recipientIdsList.add(recipientId);
            }

            private void setDateTime(long dateTime) {
                this.dateTime = dateTime;
            }

            private void setReadStatus(MessageReadStatus status) {
                this.readStatus = status;
            }

            private void setText(String text) {
                this.text = text;
            }

            private void addOtherAttributes(BlackboardAttribute attr) {
                this.otherAttributes.add(attr);
            }

            private boolean isEmpty() {
                return messageType.isEmpty() && senderId.isEmpty() && otherAttributes.isEmpty()
                        && dateTime == 0L && recipientIdsList.isEmpty()
                        && direction.equals(CommunicationDirection.UNKNOWN)
                        && subject.isEmpty() && text.isEmpty() && threadId.isEmpty()
                        && readStatus.equals(MessageReadStatus.UNKNOWN);
            }

            private Message build() {
                return new Message(this);
            }
        }
    }

    /**
     * All of the known XRY keys for message reports and their corresponding
     * blackboard attribute types, if any.
     */
    private enum XryKey {
        DELETED("deleted", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_ISDELETED),
        DIRECTION("direction", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DIRECTION),
        MESSAGE("message", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT),
        NAME_MATCHED("name (matched)", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME_PERSON),
        TEXT("text", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_TEXT),
        TIME("time", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME),
        SERVICE_CENTER("service center", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER),
        FROM("from", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_FROM),
        TO("to", BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PHONE_NUMBER_TO),
        //The following keys either need special processing or more time and data to find a type.
        STORAGE("storage", null),
        NUMBER("number", null),
        TYPE("type", null),
        TEL("tel", null),
        FOLDER("folder", null),
        NAME("name", null),
        INDEX("index", null),
        STATUS("status", null);

        private final String name;
        private final BlackboardAttribute.ATTRIBUTE_TYPE type;

        XryKey(String name, BlackboardAttribute.ATTRIBUTE_TYPE type) {
            this.name = name;
            this.type = type;
        }

        public BlackboardAttribute.ATTRIBUTE_TYPE getType() {
            return type;
        }

        public String getDisplayName() {
            return name;
        }

        /**
         * Indicates if the display name of the XRY key is a recognized type.
         *
         * @param name
         * @return
         */
        public static boolean contains(String name) {
            try {
                XryKey.fromDisplayName(name);
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
         *
         * @param name
         * @return
         */
        public static XryKey fromDisplayName(String name) {
            String normalizedName = name.trim().toLowerCase();
            for (XryKey keyChoice : XryKey.values()) {
                if (normalizedName.equals(keyChoice.name)) {
                    return keyChoice;
                }
            }

            throw new IllegalArgumentException(String.format("Key [ %s ] was not found."
                    + " All keys should be tested with contains.", name));
        }
    }

    /**
     * All of the known XRY namespaces for message reports.
     */
    private enum XryNamespace {
        FROM("from"),
        PARTICIPANT("participant"),
        TO("to"),
        NONE(null);

        private final String name;

        XryNamespace(String name) {
            this.name = name;
        }

        /**
         * Indicates if the display name of the XRY namespace is a recognized
         * type.
         *
         * @param xryNamespace
         * @return
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
         *
         * @param xryNamespace
         * @return
         */
        public static XryNamespace fromDisplayName(String xryNamespace) {
            String normalizedNamespace = xryNamespace.trim().toLowerCase();
            for (XryNamespace keyChoice : XryNamespace.values()) {
                if (normalizedNamespace.equals(keyChoice.name)) {
                    return keyChoice;
                }
            }

            throw new IllegalArgumentException(String.format("Namespace [%s] was not found."
                    + " All namespaces should be tested with contains.", xryNamespace));
        }
    }

    /**
     * All known XRY meta keys for message reports.
     */
    private enum XryMetaKey {
        REFERENCE_NUMBER("reference number"),
        SEGMENT_COUNT("segments"),
        SEGMENT_NUMBER("segment number");

        private final String name;

        XryMetaKey(String name) {
            this.name = name;
        }

        public String getDisplayName() {
            return name;
        }

        /**
         * Indicates if the display name of the XRY key is a recognized type.
         *
         * @param name
         * @return
         */
        public static boolean contains(String name) {
            try {
                XryMetaKey.fromDisplayName(name);
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
         *
         * @param name
         * @return
         */
        public static XryMetaKey fromDisplayName(String name) {
            String normalizedName = name.trim().toLowerCase();
            for (XryMetaKey keyChoice : XryMetaKey.values()) {
                if (normalizedName.equals(keyChoice.name)) {
                    return keyChoice;
                }
            }

            throw new IllegalArgumentException(String.format("Key [ %s ] was not found."
                    + " All keys should be tested with contains.", name));
        }
    }
}
