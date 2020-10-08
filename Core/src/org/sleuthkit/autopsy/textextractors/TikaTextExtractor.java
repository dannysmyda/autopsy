/*
 * Autopsy Forensic Browser
 *
 * Copyright 2011-2019 Basis Technology Corp.
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
package org.sleuthkit.autopsy.textextractors;

import com.google.common.collect.ImmutableList;
import com.google.common.io.CharSource;
import com.google.common.util.concurrent.ThreadFactoryBuilder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackReader;
import java.io.Reader;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.stream.Collectors;
import org.apache.tika.Tika;
import org.apache.tika.exception.TikaException;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.EmptyParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.parser.ParsingReader;
import org.apache.tika.parser.microsoft.OfficeParserConfig;
import org.apache.tika.parser.ocr.TesseractOCRConfig;
import org.apache.tika.parser.pdf.PDFParserConfig;
import org.openide.util.NbBundle;
import org.openide.modules.InstalledFileLocator;
import org.openide.util.Lookup;
import org.sleuthkit.autopsy.casemodule.Case;
import org.sleuthkit.autopsy.casemodule.NoCurrentCaseException;
import org.sleuthkit.autopsy.coreutils.ExecUtil;
import org.sleuthkit.autopsy.coreutils.ExecUtil.ProcessTerminator;
import org.sleuthkit.autopsy.coreutils.FileUtil;
import org.sleuthkit.autopsy.coreutils.Logger;
import org.sleuthkit.autopsy.coreutils.PlatformUtil;
import org.sleuthkit.autopsy.textextractors.configs.ImageConfig;
import org.sleuthkit.autopsy.datamodel.ContentUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Content;
import org.sleuthkit.datamodel.ReadContentInputStream;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;
import com.google.common.collect.ImmutableMap; 
import org.apache.tika.extractor.DocumentSelector;
import org.apache.tika.parser.pdf.PDFParserConfig.OCR_STRATEGY;

/**
 * Extracts text from Tika supported content. Protects against Tika parser hangs
 * (for unexpected/corrupt content) using a timeout mechanism.
 */
final class TikaTextExtractor implements TextExtractor {

    //Mimetype groups to aassist extractor implementations in ignoring binary and 
    //archive files.
    private static final List<String> BINARY_MIME_TYPES
            = ImmutableList.of(
                    //ignore binary blob data, for which string extraction will be used
                    "application/octet-stream", //NON-NLS
                    "application/x-msdownload"); //NON-NLS

    /**
     * generally text extractors should ignore archives and let unpacking
     * modules take care of them
     */
    private static final List<String> ARCHIVE_MIME_TYPES
            = ImmutableList.of(
                    //ignore unstructured binary and compressed data, for which string extraction or unzipper works better
                    "application/x-7z-compressed", //NON-NLS
                    "application/x-ace-compressed", //NON-NLS
                    "application/x-alz-compressed", //NON-NLS
                    "application/x-arj", //NON-NLS
                    "application/vnd.ms-cab-compressed", //NON-NLS
                    "application/x-cfs-compressed", //NON-NLS
                    "application/x-dgc-compressed", //NON-NLS
                    "application/x-apple-diskimage", //NON-NLS
                    "application/x-gca-compressed", //NON-NLS
                    "application/x-dar", //NON-NLS
                    "application/x-lzx", //NON-NLS
                    "application/x-lzh", //NON-NLS
                    "application/x-rar-compressed", //NON-NLS
                    "application/x-stuffit", //NON-NLS
                    "application/x-stuffitx", //NON-NLS
                    "application/x-gtar", //NON-NLS
                    "application/x-archive", //NON-NLS
                    "application/x-executable", //NON-NLS
                    "application/x-gzip", //NON-NLS
                    "application/zip", //NON-NLS
                    "application/x-zoo", //NON-NLS
                    "application/x-cpio", //NON-NLS
                    "application/x-shar", //NON-NLS
                    "application/x-tar", //NON-NLS
                    "application/x-bzip", //NON-NLS
                    "application/x-bzip2", //NON-NLS
                    "application/x-lzip", //NON-NLS
                    "application/x-lzma", //NON-NLS
                    "application/x-lzop", //NON-NLS
                    "application/x-z", //NON-NLS
                    "application/x-compress"); //NON-NLS

    //Tika should ignore types with embedded files that can be handled by the unpacking modules
    private static final List<String> EMBEDDED_FILE_MIME_TYPES
            = ImmutableList.of("application/msword", //NON-NLS
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document", //NON-NLS
                    "application/vnd.ms-powerpoint", //NON-NLS
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation", //NON-NLS
                    "application/vnd.ms-excel", //NON-NLS
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", //NON-NLS
                    "application/pdf"); //NON-NLS

    // Used to log to the tika file that is why it uses the java.util.logging.logger class instead of the Autopsy one
    private static final java.util.logging.Logger TIKA_LOGGER = java.util.logging.Logger.getLogger("Tika"); //NON-NLS
    private static final Logger AUTOPSY_LOGGER = Logger.getLogger(TikaTextExtractor.class.getName());

    private final ThreadFactory tikaThreadFactory
            = new ThreadFactoryBuilder().setNameFormat("tika-reader-%d").build();
    private final ExecutorService executorService = Executors.newSingleThreadExecutor(tikaThreadFactory);
    private static final String SQLITE_MIMETYPE = "application/x-sqlite3";

    private final AutoDetectParser parser = new AutoDetectParser();
    private final Content content;

    private boolean tesseractOCREnabled;
    private static final String TESSERACT_DIR_NAME = "Tesseract-OCR"; //NON-NLS
    private static final String TESSERACT_EXECUTABLE = "tesseract.exe"; //NON-NLS
    private static final File TESSERACT_PATH = locateTesseractExecutable();
    private String languagePacks = formatLanguagePacks(PlatformUtil.getOcrLanguagePacks());
    private static final String TESSERACT_OUTPUT_FILE_NAME = "tess_output"; //NON-NLS
    private Map<String, String> metadataMap;

    private ProcessTerminator processTerminator;

    private static final List<String> TIKA_SUPPORTED_TYPES
            = new Tika().getParser().getSupportedTypes(new ParseContext())
                    .stream()
                    .map(mt -> mt.getType() + "/" + mt.getSubtype())
                    .collect(Collectors.toList());

    public TikaTextExtractor(Content content) {
        this.content = content;
    }

    /**
     * If Tesseract has been installed and is set to be used through
     * configuration, then ocr is enabled. OCR can only currently be run on 64
     * bit Windows OS.
     *
     * @return Flag indicating if OCR is set to be used.
     */
    private boolean ocrEnabled() {
        return TESSERACT_PATH != null && tesseractOCREnabled
                && PlatformUtil.isWindowsOS() == true && PlatformUtil.is64BitOS();
    }

    /**
     * Returns a reader that will iterate over the text extracted from Apache
     * Tika.
     *
     * @param content Supported source content to extract
     *
     * @return Reader that contains Apache Tika extracted text
     *
     * @throws
     * org.sleuthkit.autopsy.textextractors.TextExtractor.TextExtractorException
     */
    @Override
    public Reader getReader() throws InitReaderException {
        InputStream stream = null;

        ParseContext parseContext = new ParseContext();

        //Disable appending embedded file text to output for EFE supported types
        //JIRA-4975
        if(content instanceof AbstractFile && EMBEDDED_FILE_MIME_TYPES.contains(((AbstractFile)content).getMIMEType())) {
            // Only allow for inline images to be selected during recursive parsing.
            // Non-visible attachments are handled by the embedded file extractor still.
            // See JIRA-6938
            parseContext.set(DocumentSelector.class, new InlineImageDocumentSelector());
        }
        
        // Needed to recursively parse embedded files
        parseContext.set(Parser.class, parser);

        if (ocrEnabled() && content instanceof AbstractFile) {
            AbstractFile file = ((AbstractFile) content);
            //Run OCR on images with Tesseract directly. 
            if (file.getMIMEType().toLowerCase().startsWith("image/")) {
                stream = performOCR(file);
            } else {
                //Otherwise, configure Tika to do OCR
                TesseractOCRConfig ocrConfig = new TesseractOCRConfig();
                String tesseractFolder = TESSERACT_PATH.getParent();
                ocrConfig.setTesseractPath(tesseractFolder);
                ocrConfig.setLanguage(languagePacks);
                ocrConfig.setTessdataPath(PlatformUtil.getOcrLanguagePacksPath());
                parseContext.set(TesseractOCRConfig.class, ocrConfig);
                
                // Configure how Tika handles PDFs and OCR
                PDFParserConfig pdfConfig = new PDFParserConfig();
                // Tesseract will run on the extracted inline images
                pdfConfig.setExtractInlineImages(true);
                // Multiple pages within a PDF file might refer to the same underlying image.
                pdfConfig.setExtractUniqueInlineImagesOnly(true);
                
                // This stategy tries to pick between OCRing a page in the 
                // PDF and doing text extraction. It makes this choice by
                // first running text extraction and then counting characters.
                // If there are too few characters, it'll run the entire page
                // through OCR and take that output instead. See JIRA-6938
                pdfConfig.setOcrStrategy(OCR_STRATEGY.AUTO);
                parseContext.set(PDFParserConfig.class, pdfConfig);

                stream = new ReadContentInputStream(content);
            }
        } else {
            stream = new ReadContentInputStream(content);
        }

        Metadata metadata = new Metadata();
        // Use the more memory efficient Tika SAX parsers for DOCX and
        // PPTX files (it already uses SAX for XLSX).
        OfficeParserConfig officeParserConfig = new OfficeParserConfig();
        officeParserConfig.setUseSAXPptxExtractor(true);
        officeParserConfig.setUseSAXDocxExtractor(true);
        parseContext.set(OfficeParserConfig.class, officeParserConfig);

        //Make the creation of a TikaReader a cancellable future in case it takes too long
        Future<Reader> future = executorService.submit(
                new GetTikaReader(parser, stream, metadata, parseContext));
        try {
            final Reader tikaReader = future.get(getTimeout(content.getSize()), TimeUnit.SECONDS);
            //check if the reader is empty
            PushbackReader pushbackReader = new PushbackReader(tikaReader);
            int read = pushbackReader.read();
            if (read == -1) {
                throw new InitReaderException("Unable to extract text: "
                        + "Tika returned empty reader for " + content);
            }
            pushbackReader.unread(read);
            
            //Save the metadata if it has not been fetched already.
            if (metadataMap == null) {
                metadataMap = new HashMap<>();
                for (String mtdtKey : metadata.names()) {
                    metadataMap.put(mtdtKey, metadata.get(mtdtKey));
                }
            }
            
            return new ReaderCharSource(pushbackReader).openStream();
        } catch (TimeoutException te) {
            final String msg = NbBundle.getMessage(this.getClass(),
                    "AbstractFileTikaTextExtract.index.tikaParseTimeout.text",
                    content.getId(), content.getName());
            throw new InitReaderException(msg, te);
        } catch (InitReaderException ex) {
            throw ex;
        } catch (Exception ex) {
            AUTOPSY_LOGGER.log(Level.WARNING, String.format("Error with file [id=%d] %s, see Tika log for details...",
                    content.getId(), content.getName()));
            TIKA_LOGGER.log(Level.WARNING, "Exception: Unable to Tika parse the "
                    + "content" + content.getId() + ": " + content.getName(),
                    ex.getCause()); //NON-NLS
            final String msg = NbBundle.getMessage(this.getClass(),
                    "AbstractFileTikaTextExtract.index.exception.tikaParse.msg",
                    content.getId(), content.getName());
            throw new InitReaderException(msg, ex);
        } finally {
            future.cancel(true);
        }
    }

    /**
     * Run OCR and return the file stream produced by Tesseract.
     *
     * @param file Image file to run OCR on
     *
     * @return InputStream connected to the output file that Tesseract produced.
     *
     * @throws
     * org.sleuthkit.autopsy.textextractors.TextExtractor.InitReaderException
     */
    private InputStream performOCR(AbstractFile file) throws InitReaderException {
        File inputFile = null;
        File outputFile = null;
        try {
            String tempDirectory = Case.getCurrentCaseThrows().getTempDirectory();

            //Appending file id makes the name unique
            String tempFileName = FileUtil.escapeFileName(file.getId() + file.getName());
            inputFile = Paths.get(tempDirectory, tempFileName).toFile();
            ContentUtils.writeToFile(content, inputFile);

            String tempOutputName = FileUtil.escapeFileName(file.getId() + TESSERACT_OUTPUT_FILE_NAME);
            String outputFilePath = Paths.get(tempDirectory, tempOutputName).toString();
            String executeablePath = TESSERACT_PATH.toString();

            //Build tesseract commands
            ProcessBuilder process = new ProcessBuilder();
            process.command(executeablePath,
                    String.format("\"%s\"", inputFile.getAbsolutePath()),
                    String.format("\"%s\"", outputFilePath),
                    "--tessdata-dir", PlatformUtil.getOcrLanguagePacksPath(),
                    //language pack command flag
                    "-l", languagePacks);

            //If the ProcessTerminator was supplied during 
            //configuration apply it here.
            if (processTerminator != null) {
                ExecUtil.execute(process, 1, TimeUnit.SECONDS, processTerminator);
            } else {
                ExecUtil.execute(process);
            }

            outputFile = new File(outputFilePath + ".txt");
            //Open a stream of the Tesseract text file and send this to Tika
            return new CleanUpStream(outputFile);
        } catch (NoCurrentCaseException | IOException ex) {
            if (outputFile != null) {
                outputFile.delete();
            }
            throw new InitReaderException("Could not successfully run Tesseract", ex);
        } finally {
            if (inputFile != null) {
                inputFile.delete();
            }
        }
    }
    
    /**
     * A document selector to control which embedded resources Tika will extract
     * and parse (or OCR). The embedded file extractor handles general embedded 
     * document extraction, but the OCR text from inline images should be part 
     * of the indexed text of the PDF document. See JIRA-6938 for more details.
     */
    private class InlineImageDocumentSelector implements DocumentSelector {

        @Override
        public boolean select(Metadata metadata) {
            String contentType = metadata.get(Metadata.CONTENT_TYPE);
            return contentType != null && contentType.toLowerCase().startsWith("image/");
        }
    }

    /**
     * Wraps the creation of a TikaReader into a Future so that it can be
     * cancelled.
     */
    private class GetTikaReader implements Callable<Reader> {

        private final AutoDetectParser parser;
        private final InputStream stream;
        private final Metadata metadata;
        private final ParseContext parseContext;

        public GetTikaReader(AutoDetectParser parser, InputStream stream,
                Metadata metadata, ParseContext parseContext) {
            this.parser = parser;
            this.stream = stream;
            this.metadata = metadata;
            this.parseContext = parseContext;
        }

        @Override
        public Reader call() throws Exception {
            return new ParsingReader(parser, stream, metadata, parseContext);
        }
    }

    /**
     * Automatically deletes the underlying File when the close() method is
     * called. This is used to delete the Output file produced from Tesseract
     * once it has been read by Tika.
     */
    private class CleanUpStream extends FileInputStream {

        private File file;

        /**
         * Store a reference to file on construction
         *
         * @param file
         *
         * @throws FileNotFoundException
         */
        public CleanUpStream(File file) throws FileNotFoundException {
            super(file);
            this.file = file;
        }

        /**
         * Delete this underlying file when close is called.
         *
         * @throws IOException
         */
        @Override
        public void close() throws IOException {
            try {
                super.close();
            } finally {
                if (file != null) {
                    file.delete();
                    file = null;
                }
            }
        }
    }

    /**
     * Finds and returns the path to the Tesseract executable, if able.
     *
     * @return A File reference or null.
     */
    private static File locateTesseractExecutable() {
        if (!PlatformUtil.isWindowsOS()) {
            return null;
        }

        String executableToFindName = Paths.get(TESSERACT_DIR_NAME, TESSERACT_EXECUTABLE).toString();
        File exeFile = InstalledFileLocator.getDefault().locate(executableToFindName, TikaTextExtractor.class.getPackage().getName(), false);
        if (null == exeFile) {
            return null;
        }

        if (!exeFile.canExecute()) {
            return null;
        }

        return exeFile;
    }

    /**
     * Get the content metadata, if any.
     *
     * @return Metadata as a name -> value map
     */
    @Override
    public Map<String, String> getMetadata() {
        if (metadataMap != null) {
            return ImmutableMap.copyOf(metadataMap);
        }
        
        try {
            metadataMap = new HashMap<>();
            InputStream stream = new ReadContentInputStream(content);
            ContentHandler doNothingContentHandler = new DefaultHandler();
            Metadata mtdt = new Metadata();
            parser.parse(stream, doNothingContentHandler, mtdt);
            for (String mtdtKey : mtdt.names()) {
                metadataMap.put(mtdtKey, mtdt.get(mtdtKey));
            }
        } catch (IOException | SAXException | TikaException ex) {
            AUTOPSY_LOGGER.log(Level.WARNING, String.format("Error getting metadata for file [id=%d] %s, see Tika log for details...", //NON-NLS
                    content.getId(), content.getName()));
            TIKA_LOGGER.log(Level.WARNING, "Exception: Unable to get metadata for " //NON-NLS
                    + "content" + content.getId() + ": " + content.getName(), ex); //NON-NLS
        }

        return metadataMap;
    }

    /**
     * Determines if Tika is enabled for this content
     *
     * @return Flag indicating support for reading content type
     */
    @Override
    public boolean isSupported() {
        if (!(content instanceof AbstractFile)) {
            return false;
        }

        String detectedType = ((AbstractFile) content).getMIMEType();
        if (detectedType == null
                || BINARY_MIME_TYPES.contains(detectedType) //any binary unstructured blobs (string extraction will be used)
                || ARCHIVE_MIME_TYPES.contains(detectedType)
                || (detectedType.startsWith("video/") && !detectedType.equals("video/x-flv")) //skip video other than flv (tika supports flv only) //NON-NLS
                || detectedType.equals(SQLITE_MIMETYPE) //Skip sqlite files, Tika cannot handle virtual tables and will fail with an exception. //NON-NLS
                ) {
            return false;
        }

        return TIKA_SUPPORTED_TYPES.contains(detectedType);
    }

    /**
     * Formats language packs to be parseable from the command line.
     *
     * @return String of all language packs available for Tesseract to use
     */
    private static String formatLanguagePacks(List<String> languagePacks) {
        return String.join("+", languagePacks);
    }

    /**
     * Return timeout that should be used to index the content.
     *
     * @param size size of the content
     *
     * @return time in seconds to use a timeout
     */
    private static int getTimeout(long size) {
        if (size < 1024 * 1024L) //1MB
        {
            return 60;
        } else if (size < 10 * 1024 * 1024L) //10MB
        {
            return 1200;
        } else if (size < 100 * 1024 * 1024L) //100MB
        {
            return 3600;
        } else {
            return 3 * 3600;
        }

    }

    /**
     * Determines how the extraction process will proceed given the settings
     * stored in this context instance.
     *
     * See the ImageConfig class in the extractionconfigs package for available
     * settings.
     *
     * @param context Instance containing config classes
     */
    @Override
    public void setExtractionSettings(Lookup context) {
        if (context != null) {
            ImageConfig configInstance = context.lookup(ImageConfig.class);
            if (configInstance != null) {
                if (Objects.nonNull(configInstance.getOCREnabled())) {
                    this.tesseractOCREnabled = configInstance.getOCREnabled();
                }

                if (Objects.nonNull(configInstance.getOCRLanguages())) {
                    this.languagePacks = formatLanguagePacks(configInstance.getOCRLanguages());
                }
            }

            ProcessTerminator terminatorInstance = context.lookup(ProcessTerminator.class);
            if (terminatorInstance != null) {
                this.processTerminator = terminatorInstance;
            }
        }
    }

    /**
     * An implementation of CharSource that just wraps an existing reader and
     * returns it in openStream().
     */
    private static class ReaderCharSource extends CharSource {

        private final Reader reader;

        ReaderCharSource(Reader reader) {
            this.reader = reader;
        }

        @Override
        public Reader openStream() throws IOException {
            return reader;
        }
    }
}
