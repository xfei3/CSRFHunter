package burp;

import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

/*
* Project template is from https://t0data.gitbooks.io/burpsuite/content/chapter16.html
* Modified by Xiejingwei Fei
* This tool is for you to check if your website has CSRF vulnerability.
* I am not responsible for any malicious use.
* */
public class BurpExtender extends AbstractTableModel implements IBurpExtender,
		ITab, IMessageEditorController, IHttpListener {
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JSplitPane splitPane;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private final List<LogEntry> log = new ArrayList<LogEntry>();
	private IHttpRequestResponse currentlyDisplayedItem;
	private boolean isOpen = true;// 插件是否生效
	private boolean isAuto = true;// ip是否自动随机生成
	private boolean isSpecify;// ip是否指定值
	private String ipValue;// 指定IP值

	private String Path_regex= ".*";
	private HashSet<String> methods = new HashSet<String>();
	private boolean showAllFlag=false,csrfTokenFlag = false, customHeaderFlag = false, doubleCookieFlag = false, encTokenFlag = false;
	private String csrfToken ="", doubleCookieValue="", encryptedTokenValue="";
	private HashSet<String> customHeaders=new HashSet<String>();

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName("Hunt CSRF"); // 插件名称
		// 开始创建自定义UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// 主面板
				splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
				JTabbedPane topTabs = new JTabbedPane();
				// HistoryLog 视图
				Table logTable = new Table(BurpExtender.this);
				JScrollPane scrollPane = new JScrollPane(logTable);
				// 创建【options】显示面板
				JPanel optionsPanel = BurpExtender.this.createOptionsPanel();

				// 添加主面板的上半部分中，分两个tab页
				topTabs.add("Options", optionsPanel);
				topTabs.add("Suspicious requests", scrollPane);
				splitPane.setLeftComponent(topTabs);

				// request/response 视图
				JTabbedPane tabs = new JTabbedPane();
				requestViewer = callbacks.createMessageEditor(
						BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(
						BurpExtender.this, false);

				// 添加主面板的下半部分中，分两个tab页
				tabs.addTab("Request", requestViewer.getComponent());
				tabs.addTab("Response", responseViewer.getComponent());
				splitPane.setRightComponent(tabs);

				// 自定义自己的组件
				callbacks.customizeUiComponent(splitPane);
				callbacks.customizeUiComponent(topTabs);
				callbacks.customizeUiComponent(tabs);

				// 在Burp添加自定义插件的tab页
				callbacks.addSuiteTab(BurpExtender.this);

				// 注册HTTP listener
				callbacks.registerHttpListener(BurpExtender.this);
			}
		});
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest,
								   IHttpRequestResponse messageInfo) {
		//如果插件未启用，则跳出不执行
		if (!isOpen)return;
		try {
			// 不同的toolflag代表了不同的burp组件，如INTRUDER,SCANNER,PROXY,SPIDER
			if (toolFlag == callbacks.TOOL_PROXY || toolFlag == callbacks.TOOL_INTRUDER
					|| toolFlag == callbacks.TOOL_SCANNER || toolFlag == callbacks.TOOL_SPIDER) {
				if (messageIsRequest) {//if you want to modify request, then do something here
//					IRequestInfo analyzeRequest = helpers
//							.analyzeRequest(messageInfo); // 对消息体进行解析
//					String request = new String(messageInfo.getRequest());
//					byte[] body = request.substring(
//							analyzeRequest.getBodyOffset()).getBytes();
//					//获取http请求头的信息，返回headers参数的列表
//					List<String> headers = analyzeRequest.getHeaders();


//					//根据IP生成方式,获取IP值
//					String ip ;
//					if(isAuto)
//						ip= this.getIpValue(true);
//					else
//						ip = this.getIpValue(false);
//					String xforward = "X-Forwarded-For: "+ ip;
//					//添加X-Forwarded-For
//					headers.add(xforward);

//
//					//重新组装请求消息
//					byte[] newRequest = helpers.buildHttpMessage(headers, body);
//					messageInfo.setRequest(newRequest);// 设置最终新的请求包
				}else {//modify response or you can check full request and response

					IRequestInfo analyzeRequest = helpers
							.analyzeRequest(messageInfo); // 对消息体进行解析
					String request = new String(messageInfo.getRequest());
					byte[] body = request.substring(
							analyzeRequest.getBodyOffset()).getBytes();
					//获取http请求头的信息，返回headers参数的列表
					List<String> headers = analyzeRequest.getHeaders();
					String url=analyzeRequest.getUrl().toString();
					boolean isMatch=Pattern.compile(Path_regex).matcher(url).matches();
					if(!showAllFlag&&!isMatch)//filter by URL
					{
						return;
					}
					if(!showAllFlag&&!methods.contains(analyzeRequest.getMethod()))//filter by HTTP method
					{
						return;
					}
					boolean record = false;//if this request needs to be recorded
					if(showAllFlag)
					{
						record=true;
					}
					if(csrfTokenFlag &&csrfToken!=null&&!csrfToken.isEmpty()) {//check CSRF token existence
						String tmpBody = "";
						if (body != null) //body may be null, but also need to check url
							{
								tmpBody = new String(body);
							}
							if (!url.contains(csrfToken) && !tmpBody.contains(csrfToken)) {
								record = true;
							}
						tmpBody= null;
					}
					if(customHeaderFlag&&headers!=null&&customHeaders.size()!=0) {//check custom header existence
						String headerName = "";
						boolean hasHeader=false;

						for (String header : headers) {
							if(!header.contains(":"))
							{
								continue;
							}
							headerName = header.substring(0, header.indexOf(":"));
							if (customHeaders.contains(headerName)) {
								hasHeader = true;
								break;
							}
						}
						//JOptionPane.showMessageDialog(null, customHeaders.size()+" "+hasHeader);
						if(!hasHeader)
						{
							record = true;
						}
					}

					if(doubleCookieFlag&&headers!=null&&doubleCookieValue!=null&&!doubleCookieValue.isEmpty())// check double cookie
					{
						boolean inCookie=false, inParameter=false;
						for(String header: headers)
						{
							if(header.startsWith("Cookie")&&header.contains(doubleCookieValue))
							{
								inCookie=true;
								break;
							}
						}
						String tmpBody = "";
						if (body != null) //body may be null, but also need to check url
							{
								tmpBody = new String(body);
							}
						if (url.contains(doubleCookieValue) || tmpBody.contains(doubleCookieValue)) {
								inParameter = true;
							}
						tmpBody= null;
						if(!(inCookie&&inParameter))
						{
							record = true;
						}
					}

					if(encTokenFlag&&encryptedTokenValue!=null&&!encryptedTokenValue.isEmpty())
					{
						boolean  inHeader = false, inBody = false;//inUrl =false,
//						if(url.contains(encryptedTokenValue))
//						{
//							inUrl= true;
//						}

						if(headers!=null)//header[0] would include parameters in URL
						{
							for(String header: headers)
							{
								if(header.contains(encryptedTokenValue))
								{
									inHeader = true;
									break;
								}
							}
						}

						String tmpBody = "";
						if (body != null)
						{
							tmpBody = new String(body);
						}
						if (tmpBody.contains(encryptedTokenValue)) {
							inBody = true;
						}
						tmpBody= null;

						if(!inHeader&&!inBody)
						{
							record = true;
						}
					}

					if(!record)
					{
						return;
					}

					//添加消息到HistoryLog记录中，供UI显示用
					synchronized (log) {
						int row = log.size();
						short httpcode = helpers.analyzeResponse(
								messageInfo.getResponse()).getStatusCode();
						log.add(new LogEntry(toolFlag, callbacks
								.saveBuffersToTempFiles(messageInfo), helpers
								.analyzeRequest(messageInfo).getUrl(), httpcode));
						fireTableRowsInserted(row, row);
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * 创建options视图对象主方法
	 * @return options 视图对象
	 * @author t0data 2016-11-18 下午5:51:45
	 */
	public JPanel createOptionsPanel() {
		final JPanel optionsPanel = new JPanel();
		optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
		//是否启用X-forward-For复选框
		final JCheckBox isOpenCheck = new JCheckBox("Enable plugin", true);
		//是否自动生成X-forward-For值单选按钮
//		final JRadioButton isAutoRadio = new JRadioButton("自动生成X-forward-For值",
//				true);
//		//是否指定X-forward-For值单选按钮
//		final JRadioButton isSpecifyRadio = new JRadioButton("指定X-forward-For值");
//		//指定IP值输入框和label
//		JLabel label = new JLabel("<html>&nbsp;&nbsp;&nbsp;&nbsp;Ip值：</html>");
//		final JTextField ipText = new JTextField("", 15);
//		ipText.setEditable(false);
//		ipText.setBackground(Color.WHITE);
//		//为复选框和单选按钮添加监听事件
		isOpenCheck.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (isOpenCheck.isSelected()) {
					isOpen = true;
				} else {
					isOpen = false;
				}
			}
		});
//
//		isAutoRadio.addItemListener(new ItemListener() {
//			public void itemStateChanged(ItemEvent e) {
//				if (isAutoRadio.isSelected()) {
//					isAuto = true;
//				} else {
//					isAuto = false;
//				}
//			}
//		});
//
//		isSpecifyRadio.addItemListener(new ItemListener() {
//			public void itemStateChanged(ItemEvent e) {
//				if (isSpecifyRadio.isSelected()) {
//					isSpecify = true;
//					ipText.setEditable(true);
//					ipText.setEnabled(true);
//
//				} else {
//					isSpecify = false;
//					ipText.setEditable(false);
//					ipText.setEnabled(false);
//					ipText.setText("");
//				}
//			}
//		});
//
//		//为IP输入框添加监听事件,失去焦距时校验IP是否符合规范
//		//并传递IP值
//		ipText.addFocusListener(new FocusListener() {
//			@Override
//			public void focusGained(FocusEvent e) {
//				// ipText.setText("");
//				ipText.setBackground(Color.LIGHT_GRAY);
//			}
//
//			@Override
//			public void focusLost(FocusEvent e) {
//				ipText.setBackground(Color.WHITE);
//				if (isSpecifyRadio.isSelected()) {
//					ipValue = ipText.getText().toString();
//					if (null == ipValue || "".equals(ipValue)) {
//						JOptionPane.showMessageDialog(optionsPanel, "请指定Ip值");
//						return;
//					} else {
//						String rexp = "([1-9]|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])(\\.(\\d|[1-9]\\d|1\\d{2}|2[0-4]\\d|25[0-5])){3}";
//						Pattern pat = Pattern.compile(rexp);
//						Matcher mat = pat.matcher(ipValue);
//						if (!mat.find()) {
//							JOptionPane.showMessageDialog(optionsPanel,
//									"Ip格式不正确");
//							return;
//						}
//					}
//				}
//			}
//		});
//		// Group the radio buttons.
//		ButtonGroup group = new ButtonGroup();
//		group.add(isAutoRadio);
//		group.add(isSpecifyRadio);

//		optionsPanel.add(isOpenCheck);
//		optionsPanel.add(isAutoRadio);
//		optionsPanel.add(isSpecifyRadio);
//		optionsPanel.add(label);
//		optionsPanel.add(ipText);

//		methods.add("GET");
		methods.add("POST");
		methods.add("PUT");
		methods.add("DELETE");


		final JPanel opt0Panel = new JPanel();
		opt0Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt1Panel = new JPanel();//basic config
		opt1Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt2Panel = new JPanel();//check CSRF token from HTML response
		opt2Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt3Panel = new JPanel();//check custom headers
		opt3Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt4Panel = new JPanel();//check double submit cookie
		opt4Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt5Panel = new JPanel();//check encrypted token
		opt5Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		final JPanel opt6Panel = new JPanel();//check same site flag
		opt6Panel.setLayout(new FlowLayout(FlowLayout.LEFT));

		opt0Panel.add(isOpenCheck);

		JLabel urlLabel = new JLabel("<html>Url regex:</html>");
		final JTextField regexText = new JTextField(Path_regex, 15);
		JLabel methodLabel = new JLabel("<html>Methods:</html>");
		final JTextField methodText = new JTextField("POST,PUT,DELETE", 15);
		final JCheckBox showAll = new JCheckBox("Show all requests", false);
		final JButton clearLog = new JButton("Clear logs");
		opt1Panel.add(urlLabel);
		opt1Panel.add(regexText);
		opt1Panel.add(methodLabel);
		opt1Panel.add(methodText);
		opt1Panel.add(showAll);
//		opt1Panel.add(clearLog);
//		clearLog.addActionListener(new ActionListener()
//		{
//			public void actionPerformed(ActionEvent e)
//			{
//				splitPane.getTopComponent().repaint();
//			}
//		});

		regexText.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateRegex();
			}
			public void removeUpdate(DocumentEvent e) {
				updateRegex();
			}
			public void insertUpdate(DocumentEvent e) {
				updateRegex();
			}

			public void updateRegex() {
				Path_regex=regexText.getText();
			}
		});

		methodText.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateMethods();
			}
			public void removeUpdate(DocumentEvent e) {
				updateMethods();
			}
			public void insertUpdate(DocumentEvent e) {
				updateMethods();
			}

			public void updateMethods() {
				String meds=methodText.getText();
				methods.clear();
				if(meds==null||meds.trim().length()==0)
				{
					return;
				}
				meds=meds.trim();
				String [] strs = meds.split(",");
				for(String str: strs)
				{
					methods.add(str.trim().toUpperCase());
				}
			}
		});

		showAll.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (showAll.isSelected()) {
					showAllFlag =true;
				} else {
					showAllFlag =false;
				}
			}
		});

		/* to do: try removing token and forging token to see if request go through */
		final JCheckBox csrfTokenEnabled = new JCheckBox("Enable", false);
		JLabel tokenLabel = new JLabel("<html>| Show request which doesn`t have string in URL/body. String value(example: csrf_token=xxx..): </html>");
		final JTextField csrfTokenField = new JTextField("", 15);
		csrfTokenField.setEditable(false);
		csrfTokenField.setBackground(Color.LIGHT_GRAY);
		opt2Panel.add(csrfTokenEnabled);
		opt2Panel.add(tokenLabel);
		opt2Panel.add(csrfTokenField);

		csrfTokenEnabled.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (csrfTokenEnabled.isSelected()) {
					csrfTokenFlag =true;
					csrfTokenField.setEditable(true);
					csrfTokenField.setBackground(Color.WHITE);
				} else {
					csrfTokenFlag =false;
					csrfTokenField.setEditable(false);
					csrfTokenField.setBackground(Color.LIGHT_GRAY);
				}
			}
		});
		csrfTokenField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateValue();
			}
			public void removeUpdate(DocumentEvent e) {
				updateValue();
			}
			public void insertUpdate(DocumentEvent e) {
				updateValue();
			}

			public void updateValue() {
				csrfToken =csrfTokenField.getText();
			}
		});

		final JCheckBox headerEnabled = new JCheckBox("Enable", false);
		JLabel headerLabel = new JLabel("<html>| Show request which doesn`t have custom headers. Header names(separated by comma): </html>");
		final JTextField customHeaderField = new JTextField("", 15);
		customHeaderField.setEditable(false);
		customHeaderField.setBackground(Color.LIGHT_GRAY);
		opt3Panel.add(headerEnabled);
		opt3Panel.add(headerLabel);
		opt3Panel.add(customHeaderField);

		headerEnabled.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (headerEnabled.isSelected()) {
					customHeaderFlag = true;
					customHeaderField.setEditable(true);
					customHeaderField.setBackground(Color.WHITE);
				} else {
					customHeaderFlag = false;
					customHeaderField.setEditable(false);
					customHeaderField.setBackground(Color.LIGHT_GRAY);
				}
			}
		});
		customHeaderField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateValue();
			}
			public void removeUpdate(DocumentEvent e) {
				updateValue();
			}
			public void insertUpdate(DocumentEvent e) {
				updateValue();
			}

			public void updateValue() {
				String heds=customHeaderField.getText();
				customHeaders.clear();
				if(heds==null||heds.trim().length()==0)
				{
					return;
				}
				heds=heds.trim();
				String [] strs = heds.split(",");
				for(String str: strs)
				{
					customHeaders.add(str.trim());
				}
			}
		});

		final JCheckBox valueEnabled = new JCheckBox("Enable", false);
		JLabel valueLabel = new JLabel("<html>| Show request which  doesn`t have value in cookie and header/URL. Value: </html>");
		final JTextField cookieValueField = new JTextField("", 15);
		cookieValueField.setEditable(false);
		cookieValueField.setBackground(Color.LIGHT_GRAY);
		opt4Panel.add(valueEnabled);
		opt4Panel.add(valueLabel);
		opt4Panel.add(cookieValueField);

		valueEnabled.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (valueEnabled.isSelected()) {
					doubleCookieFlag= true;
					cookieValueField.setEditable(true);
					cookieValueField.setBackground(Color.WHITE);
				} else {
					doubleCookieFlag = false;
					cookieValueField.setEditable(false);
					cookieValueField.setBackground(Color.LIGHT_GRAY);
				}
			}
		});
		cookieValueField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateValue();
			}
			public void removeUpdate(DocumentEvent e) {
				updateValue();
			}
			public void insertUpdate(DocumentEvent e) {
				updateValue();
			}

			public void updateValue() {
				doubleCookieValue=cookieValueField.getText();
			}
		});

		final JCheckBox encTokenEnabled = new JCheckBox("Enable", false);
		JLabel encTokenLabel = new JLabel("<html>| Show request which doesn`t have token value in Parameters and headers and body. Value: </html>");
		final JTextField encTokenValueField = new JTextField("", 15);
		encTokenValueField.setEditable(false);
		encTokenValueField.setBackground(Color.LIGHT_GRAY);
		opt5Panel.add(encTokenEnabled);
		opt5Panel.add(encTokenLabel);
		opt5Panel.add(encTokenValueField);

		encTokenEnabled.addItemListener(new ItemListener() {
			public void itemStateChanged(ItemEvent e) {
				if (encTokenEnabled.isSelected()) {
					encTokenFlag = true;
					encTokenValueField.setEditable(true);
					encTokenValueField.setBackground(Color.WHITE);
				} else {
					encTokenFlag = false;
					encTokenValueField.setEditable(false);
					encTokenValueField.setBackground(Color.LIGHT_GRAY);
				}
			}
		});
		encTokenValueField.getDocument().addDocumentListener(new DocumentListener() {
			public void changedUpdate(DocumentEvent e) {
				updateValue();
			}
			public void removeUpdate(DocumentEvent e) {
				updateValue();
			}
			public void insertUpdate(DocumentEvent e) {
				updateValue();
			}

			public void updateValue() {
				encryptedTokenValue=encTokenValueField.getText();
			}
		});

		JLabel samesiteLabel = new JLabel("<html>To do: same site flag</html>");
		opt6Panel.add(samesiteLabel);

		optionsPanel.add(opt0Panel);
		optionsPanel.add(opt1Panel);
		optionsPanel.add(opt2Panel);
		optionsPanel.add(opt3Panel);
		optionsPanel.add(opt4Panel);
		optionsPanel.add(opt5Panel);
		optionsPanel.add(opt6Panel);

		return optionsPanel;
	}

	@Override
	public String getTabCaption() {
		return "CSRFHunter";
	}

	@Override
	public Component getUiComponent() {
		return splitPane;
	}

	@Override
	public int getRowCount() {
		return log.size();
	}

	@Override
	public int getColumnCount() {
		return 3;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
			case 0:
				return "Tool";
			case 1:
				return "URL";
			case 2:
				return "STATUS";
			default:
				return "";
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		LogEntry logEntry = log.get(rowIndex);

		switch (columnIndex) {
			case 0:
				return callbacks.getToolName(logEntry.tool);
			case 1:
				return logEntry.url.toString();
			case 2:
				return logEntry.httpCode;
			default:
				return "";
		}
	}

	//
	// implement IMessageEditorController
	// this allows our request/response viewers to obtain details about the
	// messages being displayed
	//

	@Override
	public byte[] getRequest() {
		return currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse() {
		return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService() {
		return currentlyDisplayedItem.getHttpService();
	}

	//
	// extend JTable to handle cell selection
	//

	private class Table extends JTable {
		public Table(TableModel tableModel) {
			super(tableModel);
		}

		@Override
		public void changeSelection(int row, int col, boolean toggle,
									boolean extend) {
			// show the log entry for the selected row
			LogEntry logEntry = log.get(row);
			requestViewer.setMessage(logEntry.requestResponse.getRequest(),
					true);
			responseViewer.setMessage(logEntry.requestResponse.getResponse(),
					false);
			currentlyDisplayedItem = logEntry.requestResponse;
			super.changeSelection(row, col, toggle, extend);
		}
	}

	//
	// class to hold details of each log entry
	//

	private static class LogEntry {
		final int tool;
		final IHttpRequestResponsePersisted requestResponse;
		final URL url;
		final short httpCode;

		LogEntry(int tool, IHttpRequestResponsePersisted requestResponse,
				 URL url, short httpCode) {
			this.tool = tool;
			this.requestResponse = requestResponse;
			this.url = url;
			this.httpCode = httpCode;
		}
	}
}