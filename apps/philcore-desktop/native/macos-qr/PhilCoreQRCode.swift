import AppKit
import CoreImage
import CoreImage.CIFilterBuiltins
import Foundation

let input = FileHandle.standardInput.readDataToEndOfFile()
guard !input.isEmpty else {
    FileHandle.standardError.write(Data("QR_INPUT_REQUIRED\n".utf8))
    exit(2)
}

let filter = CIFilter.qrCodeGenerator()
filter.message = input
filter.correctionLevel = "M"
guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)) else {
    FileHandle.standardError.write(Data("QR_GENERATION_FAILED\n".utf8))
    exit(3)
}

let representation = NSCIImageRep(ciImage: output)
let image = NSImage(size: representation.size)
image.addRepresentation(representation)
guard let tiff = image.tiffRepresentation,
      let bitmap = NSBitmapImageRep(data: tiff),
      let png = bitmap.representation(using: .png, properties: [:]) else {
    FileHandle.standardError.write(Data("QR_ENCODING_FAILED\n".utf8))
    exit(4)
}
FileHandle.standardOutput.write(png)
