import SwiftUI

@main
struct SignrApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .frame(width: 1280, height: 740)
        }
        .windowToolbarStyle(.unified)
        .defaultSize(width: 1280, height: 740)
        .windowResizability(.contentSize)
    }
}
