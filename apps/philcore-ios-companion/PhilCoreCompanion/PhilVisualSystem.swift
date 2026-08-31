import SwiftUI
import UIKit

enum PhilPalette {
    static let background = Color.black
    static let raised = Color(white: 0.06)
    static let active = Color.white
    static let energy = Color.white
    static let text = Color.white
    static let muted = Color(white: 0.78)
    static let danger = Color.white
    static let edge = Color.white.opacity(0.2)
}

enum PhilFont {
    static func title(_ size: CGFloat = 34) -> Font {
        .custom("PixelifySans-Bold", size: size, relativeTo: .largeTitle)
    }

    static func heading(_ size: CGFloat = 22) -> Font {
        .custom("PixelifySans-SemiBold", size: size, relativeTo: .title2)
    }

    static func label(_ size: CGFloat = 14) -> Font {
        .custom("PixelifySans-Medium", size: size, relativeTo: .callout)
    }

    static func body(_ size: CGFloat = 17) -> Font {
        .system(size: size, weight: .regular, design: .default)
    }
}

struct PhilCutCornerShape: Shape {
    var cut: CGFloat = 10

    func path(in rect: CGRect) -> Path {
        let c = min(cut, min(rect.width, rect.height) / 3)
        var path = Path()
        path.move(to: CGPoint(x: rect.minX + c, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX - c, y: rect.minY))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.minY + c))
        path.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - c))
        path.addLine(to: CGPoint(x: rect.maxX - c, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX + c, y: rect.maxY))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.maxY - c))
        path.addLine(to: CGPoint(x: rect.minX, y: rect.minY + c))
        path.closeSubpath()
        return path
    }
}

struct PhilBackdrop: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        ZStack {
            if let path = Bundle.main.path(
                forResource: "philenator_bg",
                ofType: "png",
                inDirectory: "Characters"
            ), let image = UIImage(contentsOfFile: path) {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFill()
                    .saturation(1.08)
                    .contrast(1.18)
                    .brightness(-0.24)
                    .opacity(0.46)
            }
            LinearGradient(
                colors: [Color.black.opacity(0.42), Color.black.opacity(0.72)],
                startPoint: .top,
                endPoint: .bottom
            )
            if !reduceMotion {
                Canvas { context, size in
                    for index in 0..<18 {
                        let x = CGFloat((index * 83) % 397) / 397 * size.width
                        let y = CGFloat((index * 137) % 719) / 719 * size.height
                        context.fill(
                            Path(ellipseIn: CGRect(x: x, y: y, width: 1.5, height: 1.5)),
                            with: .color(Color.white.opacity(0.08))
                        )
                    }
                }
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

struct PhilSurface<Content: View>: View {
    let tone: Tone
    let content: Content

    enum Tone { case standard, elevated, warning }

    init(tone: Tone = .standard, @ViewBuilder content: () -> Content) {
        self.tone = tone
        self.content = content()
    }

    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(background, in: PhilCutCornerShape())
            .overlay(PhilCutCornerShape().stroke(border, lineWidth: 1))
    }

    private var background: Color {
        switch tone {
        case .standard: PhilPalette.background.opacity(0.94)
        case .elevated: PhilPalette.raised.opacity(0.97)
        case .warning: Color(white: 0.08).opacity(0.97)
        }
    }

    private var border: Color {
        tone == .warning ? PhilPalette.danger.opacity(0.85) : PhilPalette.edge
    }
}

struct PhilBrandHeader: View {
    let title: String
    let subtitle: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(PhilFont.title())
                .foregroundStyle(PhilPalette.text)
                .fixedSize(horizontal: false, vertical: true)
            Text(subtitle)
                .font(PhilFont.body(16))
                .foregroundStyle(PhilPalette.muted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
    }
}

struct PhilCharacterArtwork: View {
    let asset: String
    var width: CGFloat = 112
    var accessibilityLabel: String

    var body: some View {
        Group {
            if let image = loadImage() {
                Image(uiImage: image)
                    .resizable()
                    .interpolation(.none)
                    .scaledToFit()
            } else {
                Image(systemName: "shield.checkered")
                    .resizable()
                    .scaledToFit()
                    .foregroundStyle(PhilPalette.active)
                    .padding(18)
            }
        }
        .frame(width: width, height: width * 1.08)
        .accessibilityLabel(accessibilityLabel)
    }

    private func loadImage() -> UIImage? {
        guard let path = Bundle.main.path(
            forResource: asset,
            ofType: "png",
            inDirectory: "Characters"
        ) else { return nil }
        return UIImage(contentsOfFile: path)
    }
}

struct PhilGuideCard: View {
    let asset: String
    let title: String
    let message: String
    let accessibilityLabel: String
    var compact = false

    var body: some View {
        PhilSurface(tone: .elevated) {
            HStack(alignment: .center, spacing: 14) {
                PhilCharacterArtwork(
                    asset: asset,
                    width: compact ? 72 : 96,
                    accessibilityLabel: accessibilityLabel
                )
                VStack(alignment: .leading, spacing: 6) {
                    Text(title.uppercased())
                        .font(PhilFont.label(13))
                        .foregroundStyle(PhilPalette.active)
                        .tracking(0.8)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(message)
                        .font(PhilFont.body(compact ? 15 : 16))
                        .foregroundStyle(PhilPalette.text)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

enum PhilStateTone {
    case success, warning, blocked, rejected, failed, unknown

    var label: String {
        switch self {
        case .success: "Success"
        case .warning: "Warning"
        case .blocked: "Blocked"
        case .rejected: "Rejected"
        case .failed: "Failed"
        case .unknown: "Status unknown"
        }
    }

    var icon: String {
        switch self {
        case .success: "checkmark.seal.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .blocked: "hand.raised.fill"
        case .rejected: "xmark.seal.fill"
        case .failed: "exclamationmark.octagon.fill"
        case .unknown: "questionmark.diamond.fill"
        }
    }
}

struct PhilStateCard: View {
    let tone: PhilStateTone
    let title: String
    let message: String

    var body: some View {
        PhilSurface(tone: tone == .warning ? .warning : .elevated) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: tone.icon)
                    .font(.title2)
                    .foregroundStyle(PhilPalette.active)
                    .frame(width: 30)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 5) {
                    Text(tone.label.uppercased())
                        .font(PhilFont.label(12))
                        .foregroundStyle(PhilPalette.muted)
                        .tracking(0.8)
                    Text(title)
                        .font(PhilFont.heading(20))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(message)
                        .font(PhilFont.body(15))
                        .foregroundStyle(PhilPalette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .accessibilityElement(children: .combine)
    }
}

struct PhilProgressCard: View {
    let stage: String
    let detail: String

    var body: some View {
        PhilSurface(tone: .elevated) {
            HStack(alignment: .top, spacing: 14) {
                ProgressView()
                    .tint(PhilPalette.active)
                    .controlSize(.large)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 5) {
                    Text("IN PROGRESS")
                        .font(PhilFont.label(12))
                        .foregroundStyle(PhilPalette.muted)
                        .tracking(0.8)
                    Text(stage)
                        .font(PhilFont.heading(20))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(detail)
                        .font(PhilFont.body(15))
                        .foregroundStyle(PhilPalette.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.updatesFrequently)
    }
}

struct PhilSectionLabel: View {
    let text: String
    var body: some View {
        HStack(spacing: 8) {
            Rectangle().fill(PhilPalette.energy).frame(width: 3, height: 16)
            Text(text.uppercased())
                .font(PhilFont.label(13))
                .foregroundStyle(PhilPalette.active)
                .tracking(0.8)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityAddTraits(.isHeader)
    }
}

struct PhilButtonStyle: ButtonStyle {
    enum Tone { case primary, secondary, destructive }
    let tone: Tone
    @Environment(\.isEnabled) private var isEnabled
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(PhilFont.label(17))
            .foregroundStyle(foreground.opacity(isEnabled ? 1 : 0.45))
            .padding(.horizontal, 16)
            .frame(minHeight: 52)
            .background(background.opacity(pressedOpacity(configuration)), in: PhilCutCornerShape(cut: 8))
            .overlay(PhilCutCornerShape(cut: 8).stroke(border, lineWidth: 1))
            .scaleEffect((!reduceMotion && configuration.isPressed) ? 0.985 : 1)
    }

    private func pressedOpacity(_ configuration: Configuration) -> Double {
        if !isEnabled { return 0.55 }
        return configuration.isPressed ? 0.78 : 1
    }

    private var foreground: Color {
        tone == .primary ? Color.black : PhilPalette.text
    }

    private var background: Color {
        switch tone {
        case .primary: PhilPalette.active
        case .secondary: PhilPalette.raised
        case .destructive: Color.white.opacity(0.08)
        }
    }

    private var border: Color {
        switch tone {
        case .primary: PhilPalette.active
        case .secondary: PhilPalette.edge
        case .destructive: Color.white.opacity(0.7)
        }
    }
}

extension ButtonStyle where Self == PhilButtonStyle {
    static var philPrimary: PhilButtonStyle { PhilButtonStyle(tone: .primary) }
    static var philSecondary: PhilButtonStyle { PhilButtonStyle(tone: .secondary) }
    static var philDestructive: PhilButtonStyle { PhilButtonStyle(tone: .destructive) }
}

enum PhilAppearance {
    static func configure() {
        let tab = UITabBarAppearance()
        tab.configureWithOpaqueBackground()
        tab.backgroundColor = UIColor(white: 0.03, alpha: 0.98)
        tab.shadowColor = UIColor.white.withAlphaComponent(0.12)
        let items = [tab.stackedLayoutAppearance, tab.inlineLayoutAppearance, tab.compactInlineLayoutAppearance]
        for item in items {
            item.normal.iconColor = UIColor(PhilPalette.muted)
            item.normal.titleTextAttributes = [
                .foregroundColor: UIColor(PhilPalette.muted),
                .font: UIFont.systemFont(ofSize: 11, weight: .medium)
            ]
            item.selected.iconColor = UIColor(PhilPalette.active)
            item.selected.titleTextAttributes = [
                .foregroundColor: UIColor(PhilPalette.active),
                .font: UIFont(name: "PixelifySans-Medium", size: 12) ?? UIFont.systemFont(ofSize: 12, weight: .semibold)
            ]
        }
        UITabBar.appearance().standardAppearance = tab
        UITabBar.appearance().scrollEdgeAppearance = tab

        let navigation = UINavigationBarAppearance()
        navigation.configureWithTransparentBackground()
        navigation.backgroundColor = UIColor.clear
        navigation.titleTextAttributes = [
            .foregroundColor: UIColor(PhilPalette.text),
            .font: UIFont(name: "PixelifySans-SemiBold", size: 19) ?? UIFont.systemFont(ofSize: 19, weight: .semibold)
        ]
        navigation.largeTitleTextAttributes = [
            .foregroundColor: UIColor(PhilPalette.text),
            .font: UIFont(name: "PixelifySans-Bold", size: 32) ?? UIFont.systemFont(ofSize: 32, weight: .bold)
        ]
        UINavigationBar.appearance().standardAppearance = navigation
        UINavigationBar.appearance().scrollEdgeAppearance = navigation
        UINavigationBar.appearance().compactAppearance = navigation
    }
}

extension View {
    func philScreen() -> some View {
        self
            .font(PhilFont.body())
            .foregroundStyle(PhilPalette.text)
            .background(PhilBackdrop())
    }
}
