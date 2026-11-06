using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;
using WiFiTransfer.App.Services;

namespace WiFiTransfer.App;

public sealed class SharedFoldersWindow : Window
{
    private static readonly Brush BackgroundBrush = Brush("#0B1220");
    private static readonly Brush CardBrush = Brush("#172235");
    private static readonly Brush MutedBrush = Brush("#9AAAC0");
    private static readonly Brush AccentBrush = Brush("#8B7CF6");
    private readonly SharedFolderStore _store;
    private readonly StackPanel _folderList = new();
    private readonly TextBlock _summary = new();

    public SharedFoldersWindow(SharedFolderStore store)
    {
        _store = store;
        Title = "Shared folders · DroidShare-WiFi";
        Width = 820;
        Height = 650;
        MinWidth = 700;
        MinHeight = 520;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = BackgroundBrush;
        Foreground = Brushes.White;
        FontFamily = new FontFamily("Segoe UI");

        var root = new Grid { Margin = new Thickness(26) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var header = new DockPanel { LastChildFill = true, Margin = new Thickness(0, 0, 0, 20) };
        var add = MakeButton("+  Add folder", AccentBrush, Brushes.White);
        add.MinWidth = 142;
        add.Click += AddFolder_Click;
        DockPanel.SetDock(add, Dock.Right);
        header.Children.Add(add);
        var titleStack = new StackPanel();
        titleStack.Children.Add(new TextBlock
        {
            Text = "Your shared folders", FontSize = 25, FontWeight = FontWeights.SemiBold
        });
        titleStack.Children.Add(new TextBlock
        {
            Text = "Only folders you add here can be made available to paired devices.",
            Foreground = MutedBrush, FontSize = 13, Margin = new Thickness(0, 5, 12, 0)
        });
        header.Children.Add(titleStack);
        Grid.SetRow(header, 0);
        root.Children.Add(header);

        var info = new Border
        {
            Background = Brush("#202D43"), CornerRadius = new CornerRadius(12),
            Padding = new Thickness(14), Margin = new Thickness(0, 0, 0, 16)
        };
        info.Child = new TextBlock
        {
            Text = "Privacy first  ·  New folders default to Read + Stream. Write and Delete stay off until you explicitly enable them.",
            Foreground = Brush("#D7E1F0"), TextWrapping = TextWrapping.Wrap, FontSize = 13
        };
        Grid.SetRow(info, 1);
        root.Children.Add(info);

        var scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
        _folderList.Margin = new Thickness(0, 0, 4, 0);
        scroll.Content = _folderList;
        Grid.SetRow(scroll, 2);
        root.Children.Add(scroll);

        var footer = new DockPanel { Margin = new Thickness(0, 16, 0, 0) };
        _summary.Foreground = MutedBrush;
        _summary.VerticalAlignment = VerticalAlignment.Center;
        footer.Children.Add(_summary);
        var close = MakeButton("Done", Brush("#29364B"), Brushes.White);
        close.MinWidth = 100;
        close.Click += (_, _) => Close();
        DockPanel.SetDock(close, Dock.Right);
        footer.Children.Add(close);
        Grid.SetRow(footer, 3);
        root.Children.Add(footer);

        Content = root;
        RefreshFolders();
    }

    private void AddFolder_Click(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFolderDialog
        {
            Title = "Choose a folder to share",
            Multiselect = false
        };
        if (picker.ShowDialog(this) != true) return;

        try
        {
            _store.Add(picker.FolderName);
            RefreshFolders();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
        {
            MessageBox.Show(this, ex.Message, "Could not share folder",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RefreshFolders()
    {
        _folderList.Children.Clear();
        var shares = _store.GetAll();
        foreach (var share in shares)
            _folderList.Children.Add(CreateFolderCard(share));

        if (shares.Count == 0)
        {
            var empty = new Border
            {
                Background = CardBrush, CornerRadius = new CornerRadius(14), Padding = new Thickness(28),
                Margin = new Thickness(0, 0, 0, 12)
            };
            var stack = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
            stack.Children.Add(new TextBlock
            {
                Text = "No folders shared yet", FontSize = 18, FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center
            });
            stack.Children.Add(new TextBlock
            {
                Text = "Add a folder to create your private sharing space.",
                Foreground = MutedBrush, Margin = new Thickness(0, 8, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Center
            });
            empty.Child = stack;
            _folderList.Children.Add(empty);
        }

        _summary.Text = $"{shares.Count} folder{(shares.Count == 1 ? "" : "s")} configured  ·  Changes are saved on this PC";
    }

    private Border CreateFolderCard(SharedFolderShare share)
    {
        var card = new Border
        {
            Background = CardBrush, CornerRadius = new CornerRadius(14),
            Padding = new Thickness(16), Margin = new Thickness(0, 0, 0, 12)
        };
        var layout = new Grid();
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        layout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var top = new DockPanel { LastChildFill = true };
        var remove = MakeButton("Remove", Brush("#3A2733"), Brush("#FDA4AF"));
        remove.Padding = new Thickness(12, 6, 12, 6);
        remove.Click += (_, _) => RemoveFolder(share);
        DockPanel.SetDock(remove, Dock.Right);
        top.Children.Add(remove);

        var name = new TextBlock
        {
            Text = "▰  " + share.DisplayName, FontSize = 17, FontWeight = FontWeights.SemiBold,
            Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center
        };
        top.Children.Add(name);
        Grid.SetRow(top, 0);
        layout.Children.Add(top);

        var path = new TextBlock
        {
            Text = share.RootPath, Foreground = MutedBrush, FontSize = 12,
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 7, 0, 12)
        };
        Grid.SetRow(path, 1);
        layout.Children.Add(path);

        var permissions = new WrapPanel { Orientation = Orientation.Horizontal };
        AddPermission(permissions, "Read", share.CanRead, value => Update(share, value, share.CanWrite, share.CanDelete, share.CanStream));
        AddPermission(permissions, "Write", share.CanWrite, value => Update(share, share.CanRead, value, share.CanDelete, share.CanStream));
        AddPermission(permissions, "Delete", share.CanDelete, value => Update(share, share.CanRead, share.CanWrite, value, share.CanStream));
        AddPermission(permissions, "Stream", share.CanStream, value => Update(share, share.CanRead, share.CanWrite, share.CanDelete, value));
        Grid.SetRow(permissions, 2);
        layout.Children.Add(permissions);

        card.Child = layout;
        return card;
    }

    private void AddPermission(Panel panel, string label, bool enabled, Action<bool> changed)
    {
        var check = new CheckBox
        {
            Content = label, IsChecked = enabled, Foreground = Brush("#E5ECF5"),
            FontSize = 13, Margin = new Thickness(0, 0, 24, 0), VerticalAlignment = VerticalAlignment.Center
        };
        check.Checked += (_, _) => changed(true);
        check.Unchecked += (_, _) => changed(false);
        panel.Children.Add(check);
    }

    private void Update(SharedFolderShare share, bool read, bool write, bool delete, bool stream)
    {
        try
        {
            _store.UpdatePermissions(share.ShareId, read, write, delete, stream);
            RefreshFolders();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
        {
            MessageBox.Show(this, ex.Message, "Permission not saved",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            RefreshFolders();
        }
    }

    private void RemoveFolder(SharedFolderShare share)
    {
        if (MessageBox.Show(this,
                $"Remove \"{share.DisplayName}\" from sharing? Files on disk will not be deleted.",
                "Remove shared folder", MessageBoxButton.YesNo, MessageBoxImage.Question,
                MessageBoxResult.No) != MessageBoxResult.Yes) return;
        _store.Remove(share.ShareId);
        RefreshFolders();
    }

    private static Button MakeButton(string text, Brush background, Brush foreground) => new()
    {
        Content = text, Background = background, Foreground = foreground,
        BorderThickness = new Thickness(0), Padding = new Thickness(16, 9, 16, 9),
        FontWeight = FontWeights.SemiBold, Cursor = System.Windows.Input.Cursors.Hand
    };

    private static SolidColorBrush Brush(string color) =>
        new((Color)new ColorConverter().ConvertFromString(color));
}
